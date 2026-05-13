mod app;
mod event;
mod render;

pub use app::{App, AppState};
pub use event::EventHandler;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::stdout;
use tokio::sync::mpsc;

use crate::event::NormalizedEvent;

/// TUI entry point — initialize terminal → main loop → restore terminal.
/// event_rx: channel for receiving processed events (if None, runs without events).
/// Falls back to headless mode (logging only) when no TTY is available.
pub async fn run(app: App, mut event_rx: Option<mpsc::Receiver<NormalizedEvent>>) -> Result<()> {
    // Attempt to enter raw mode; if no TTY is attached (e.g. Docker/systemd
    // service), fall back to a headless loop that keeps the daemon running.
    if enable_raw_mode().is_err() {
        return run_headless(&mut event_rx).await;
    }

    if execute!(stdout(), EnterAlternateScreen).is_err() {
        let _ = disable_raw_mode();
        return run_headless(&mut event_rx).await;
    }

    // Restore terminal on panic so the shell isn't left in raw mode
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        hook(info);
    }));

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_loop(&mut terminal, app, &mut event_rx).await;

    // Always restore terminal, even on error
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

/// Headless fallback: drain the event channel and log events, keeping the
/// daemon alive until the channel is closed (process killed / SIGTERM).
async fn run_headless(event_rx: &mut Option<mpsc::Receiver<NormalizedEvent>>) -> Result<()> {
    tracing::info!("No TTY detected — running in headless (log-only) mode");
    loop {
        match event_rx.as_mut() {
            Some(rx) => match rx.recv().await {
                Some(ev) => tracing::info!(
                    event = ?ev.event_type,
                    pid = ev.process.pid,
                    binary = %ev.process.binary,
                    action = ?ev.action,
                    "event"
                ),
                None => {
                    // Pipeline closed (e.g. eBPF failed); stay alive, keep
                    // logging "no events" rather than exiting the daemon.
                    tracing::warn!("Event pipeline closed — running in degraded mode");
                    *event_rx = None;
                }
            },
            None => {
                // No event source — sleep until cancelled
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
            }
        }
    }
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    mut app: App,
    event_rx: &mut Option<mpsc::Receiver<NormalizedEvent>>,
) -> Result<()> {
    let mut key_handler = EventHandler::new(50); // 50ms polling
    let pending_refresh = std::time::Duration::from_millis(500);

    loop {
        app.maybe_refresh_pending(pending_refresh);
        terminal.draw(|f| render::draw(f, &app))?;

        tokio::select! {
            // Handle keyboard events
            quit = key_handler.handle(&mut app) => {
                if quit? { break; }
            }
            // Receive event stream (never becomes ready if None)
            Some(ev) = async {
                if let Some(rx) = event_rx.as_mut() { rx.recv().await } else { None }
            } => {
                app.push_event(&ev);
            }
        }

        if app.state == AppState::Quit {
            break;
        }
    }

    Ok(())
}
