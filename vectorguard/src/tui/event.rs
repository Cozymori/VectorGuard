use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

use super::app::{App, AppState, InputMode, Tab};
use super::app::FieldType;

pub struct EventHandler {
    tick_ms: u64,
}

impl EventHandler {
    pub fn new(tick_ms: u64) -> Self {
        Self { tick_ms }
    }

    /// Handle key events. Returns true to exit the loop.
    pub async fn handle(&mut self, app: &mut App) -> Result<bool> {
        let available = tokio::task::spawn_blocking(|| {
            event::poll(Duration::from_millis(0))
        })
        .await??;

        if !available {
            tokio::time::sleep(Duration::from_millis(self.tick_ms)).await;
            return Ok(false);
        }

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                return Ok(false);
            }

            // 1순위: 상세 팝업이 열려 있으면 Esc/q로만 닫기
            if app.is_detail_open() {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                        app.close_detail();
                    }
                    _ => {}
                }
                return Ok(false);
            }

            // 2순위: config 편집 모드
            if app.config_editing {
                match key.code {
                    KeyCode::Esc => { app.cancel_config_edit(); }
                    KeyCode::Enter => { app.confirm_config_edit(); }
                    KeyCode::Backspace => { app.config_edit_buf.pop(); }
                    KeyCode::Char(c) => {
                        // For bool fields, toggle directly without typing
                        if let Some(f) = app.config_fields.get(app.config_field_idx) {
                            if f.field_type == FieldType::Bool {
                                let toggled = if app.config_edit_buf == "true" { "false" } else { "true" };
                                app.config_edit_buf = toggled.to_string();
                                app.confirm_config_edit();
                                return Ok(false);
                            }
                        }
                        app.config_edit_buf.push(c);
                    }
                    _ => {}
                }
                return Ok(false);
            }

            // 3순위: 필터 입력 모드
            if app.input_mode == InputMode::Filtering {
                match key.code {
                    KeyCode::Esc => {
                        app.filter_input.clear();
                        app.filter_query.clear();
                        app.input_mode = InputMode::Normal;
                    }
                    KeyCode::Enter => {
                        app.filter_query = app.filter_input.clone();
                        app.input_mode = InputMode::Normal;
                        app.event_scroll = 0;
                    }
                    KeyCode::Char(c) => {
                        app.filter_input.push(c);
                    }
                    KeyCode::Backspace => {
                        app.filter_input.pop();
                    }
                    _ => {}
                }
                return Ok(false);
            }

            // 3순위: 일반 모드
            match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                    app.state = AppState::Quit;
                    return Ok(true);
                }
                KeyCode::Tab               => app.next_tab(),
                KeyCode::Char('1')         => app.active_tab = Tab::Dashboard,
                KeyCode::Char('2')         => app.active_tab = Tab::Events,
                KeyCode::Char('3')         => app.active_tab = Tab::Incidents,
                KeyCode::Char('4')         => app.active_tab = Tab::Config,
                KeyCode::Char('5')         => app.active_tab = Tab::ProcessTree,
                KeyCode::Up   | KeyCode::Char('k') => app.scroll_up(),
                KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                KeyCode::Enter => {
                    match app.active_tab {
                        Tab::Events | Tab::Incidents => app.open_detail(),
                        Tab::Config => app.start_config_edit(),
                        _ => {}
                    }
                }
                KeyCode::Char('e') if app.active_tab == Tab::Config => {
                    app.start_config_edit();
                }
                KeyCode::Char('s') if app.active_tab == Tab::Config => {
                    app.save_config();
                }
                KeyCode::Char('f') => {
                    if app.active_tab == Tab::Incidents {
                        app.cycle_incident_filter();
                    }
                }
                KeyCode::Char('/') => {
                    if app.active_tab == Tab::Events {
                        app.input_mode = InputMode::Filtering;
                        app.filter_input.clear();
                    }
                }
                _ => {}
            }
        }

        Ok(false)
    }
}
