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

/// TUI 진입점 — 터미널 초기화 → 메인 루프 → 복원
/// event_rx: 처리된 이벤트 수신 채널 (None이면 이벤트 없이 실행)
pub async fn run(app: App, mut event_rx: Option<mpsc::Receiver<NormalizedEvent>>) -> Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, app, &mut event_rx).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    mut app: App,
    event_rx: &mut Option<mpsc::Receiver<NormalizedEvent>>,
) -> Result<()> {
    let mut key_handler = EventHandler::new(50); // 50ms 폴링

    loop {
        terminal.draw(|f| render::draw(f, &app))?;

        tokio::select! {
            // 키보드 이벤트 처리
            quit = key_handler.handle(&mut app) => {
                if quit? { break; }
            }
            // 이벤트 스트림 수신 (None이면 절대 ready되지 않음)
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
