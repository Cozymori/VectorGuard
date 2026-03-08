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

    /// 키 이벤트 처리. true 반환 시 루프 종료.
    /// tokio::select! 내에서 호출되므로 짧은 timeout 사용
    pub async fn handle(&mut self, app: &mut App) -> Result<bool> {
        // 짧게 폴링 — tokio::select!가 다른 브랜치와 병행 처리
        let available = tokio::task::spawn_blocking(|| {
            event::poll(Duration::from_millis(0))
        })
        .await??;

        if !available {
            // 이벤트 없음 → 짧게 yield 후 반환
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
