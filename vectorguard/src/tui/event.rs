use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

use super::app::{App, AppState, Tab};

pub struct EventHandler {
    tick_ms: u64,
}

impl EventHandler {
    pub fn new(tick_ms: u64) -> Self {
        Self { tick_ms }
    }

    /// Handle key events. Returns true to exit the loop.
    /// Uses a short timeout because it is called inside tokio::select!
    pub async fn handle(&mut self, app: &mut App) -> Result<bool> {
        // Poll briefly — tokio::select! handles concurrency with other branches
        let available = tokio::task::spawn_blocking(|| {
            event::poll(Duration::from_millis(0))
        })
        .await??;

        if !available {
            // No event → yield briefly and return
            tokio::time::sleep(Duration::from_millis(self.tick_ms)).await;
            return Ok(false);
        }

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(false);
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                    app.state = AppState::Quit;
                    return Ok(true);
                }
                KeyCode::Tab               => app.next_tab(),
                KeyCode::Char('1')         => app.active_tab = Tab::Dashboard,
                KeyCode::Char('2')         => app.active_tab = Tab::Events,
                KeyCode::Char('3')         => app.active_tab = Tab::Config,
                KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                _ => {}
            }
        }

        Ok(false)
    }
}
