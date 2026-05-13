use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
};

use super::app::{App, InputMode, Tab};
use crate::event::Severity;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // 전체 배경을 검정으로 채워 터미널 잔상 제거
    let bg = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(bg, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // tab bar
            Constraint::Min(0),     // body
            Constraint::Length(1),  // footer
        ])
        .split(area);

    draw_tabs(f, app, chunks[0]);

    match app.active_tab {
        Tab::Dashboard   => draw_dashboard(f, app, chunks[1]),
        Tab::Events      => draw_events(f, app, chunks[1]),
        Tab::Incidents   => draw_incidents(f, app, chunks[1]),
        Tab::Config      => draw_config(f, app, chunks[1]),
        Tab::ProcessTree => draw_process_tree(f, app, chunks[1]),
        Tab::Pending     => draw_pending(f, app, chunks[1]),
    }

    draw_footer(f, app, chunks[2]);

    // 팝업은 맨 마지막에 렌더링 (최상단 레이어)
    if let Some(idx) = app.selected_incident {
        let incidents = app.filtered_incidents();
        if let Some(inc) = incidents.get(idx) {
            draw_incident_detail(f, inc, area);
        }
    } else if let Some(idx) = app.selected_event {
        let events = app.filtered_events();
        if let Some(ev) = events.get(idx) {
            draw_event_detail(f, ev, area);
        }
    } else if let Some(idx) = app.selected_pending {
        if let Some(p) = app.pending.get(idx) {
            draw_pending_detail(f, p, area);
        }
    }
}

// ── Tab Bar ───────────────────────────────────────────────────
fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::titles()
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(Span::styled(
                format!(" {} {} ", i + 1, t),
                Style::default().fg(Color::White),
            ))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" VectorGuard "))
        .select(app.active_tab.index())
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

// ── Dashboard ─────────────────────────────────────────────────
fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let stat_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    let s = &app.stats;
    draw_stat_card(f, "Total Events",  &s.total_events.to_string(),  Color::White,   stat_chunks[0]);
    draw_stat_card(f, "Blocked",       &s.blocked.to_string(),        Color::Red,     stat_chunks[1]);
    draw_stat_card(f, "Alerts",        &s.alerts.to_string(),         Color::Yellow,  stat_chunks[2]);
    draw_stat_card(f, "High Severity", &s.high_severity.to_string(),  Color::Magenta, stat_chunks[3]);

    draw_recent_events(f, app, chunks[1]);
}

fn draw_stat_card(f: &mut Frame, title: &str, value: &str, color: Color, area: Rect) {
    let text = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", value),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title(format!(" {} ", title))
        .style(Style::default().bg(Color::Black)));
    f.render_widget(text, area);
}

fn draw_recent_events(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Time", "PID", "Process", "Kind", "Severity", "Action"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let recent: Vec<Row> = app.events.iter().rev().take(20).map(|e| {
        let sev_color = severity_color(&e.severity);
        let action_color = action_color(&e.action);
        Row::new(vec![
            Cell::from(e.timestamp.as_str()),
            Cell::from(e.pid.to_string()),
            Cell::from(e.process.as_str()),
            Cell::from(e.kind.as_str()),
            Cell::from(Span::styled(format!("{:?}", e.severity), Style::default().fg(sev_color))),
            Cell::from(Span::styled(e.action.as_str(), Style::default().fg(action_color))),
        ])
        .height(1)
    }).collect();

    let table = Table::new(recent, [
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(16),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(8),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Recent Events ")
        .style(Style::default().bg(Color::Black)))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);
}

// ── Events Tab ────────────────────────────────────────────────
fn draw_events(f: &mut Frame, app: &App, area: Rect) {
    // 필터 검색창 영역 분리
    let (table_area, search_area_opt) = if app.input_mode == InputMode::Filtering
        || !app.filter_query.is_empty()
    {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(3)])
            .split(area);
        (chunks[0], Some(chunks[1]))
    } else {
        (area, None)
    };

    let header = Row::new(vec!["Time", "PID", "Process", "Kind", "Severity", "Action"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let events = app.filtered_events();
    let rows: Vec<Row> = events.iter().map(|e| {
        let sev_color = severity_color(&e.severity);
        let action_color = action_color(&e.action);
        Row::new(vec![
            Cell::from(e.timestamp.as_str()),
            Cell::from(e.pid.to_string()),
            Cell::from(e.process.as_str()),
            Cell::from(e.kind.as_str()),
            Cell::from(Span::styled(format!("{:?}", e.severity), Style::default().fg(sev_color))),
            Cell::from(Span::styled(e.action.as_str(), Style::default().fg(action_color))),
        ])
        .height(1)
    }).collect();

    let title = if app.filter_query.is_empty() {
        " All Events (↑↓ scroll  Enter detail  / filter) ".to_string()
    } else {
        format!(" Filtered: \"{}\" ({} results) ", app.filter_query, events.len())
    };

    let mut state = TableState::default();
    if !events.is_empty() {
        state.select(Some(app.event_scroll));
    }

    let table = Table::new(rows, [
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(16),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(8),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title)
        .style(Style::default().bg(Color::Black)))
    .row_highlight_style(Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD));

    f.render_stateful_widget(table, table_area, &mut state);

    // 검색창 렌더링
    if let Some(sa) = search_area_opt {
        let search_text = if app.input_mode == InputMode::Filtering {
            format!("{}_", app.filter_input)
        } else {
            format!("{}  (Esc to clear)", app.filter_query)
        };
        let border_color = if app.input_mode == InputMode::Filtering {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let p = Paragraph::new(search_text)
            .block(Block::default().borders(Borders::ALL).title(" Filter (/) ")
                .border_style(Style::default().fg(border_color))
                .style(Style::default().bg(Color::Black)));
        f.render_widget(p, sa);
    }
}

// ── Incidents Tab ─────────────────────────────────────────────
fn draw_incidents(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Time", "PID", "Process", "Kind", "Rule", "Action"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let incidents = app.filtered_incidents();
    let rows: Vec<Row> = incidents.iter().map(|i| {
        let action_color = action_color(&i.action);
        Row::new(vec![
            Cell::from(i.timestamp.as_str()),
            Cell::from(i.pid.to_string()),
            Cell::from(i.process.as_str()),
            Cell::from(i.kind.as_str()),
            Cell::from(Span::styled(i.rule.as_str(), Style::default().fg(Color::Yellow))),
            Cell::from(Span::styled(i.action.as_str(), Style::default().fg(action_color))),
        ])
        .height(1)
    }).collect();

    let filter_label = match app.incident_filter {
        super::app::IncidentFilter::All     => "All",
        super::app::IncidentFilter::Blocked => "Blocked",
        super::app::IncidentFilter::Alerted => "Alerted",
    };
    let title = format!(
        " Incidents [{}] ({} total) — Tab:filter  ↑↓:scroll  Enter:detail ",
        filter_label, incidents.len()
    );

    let mut state = TableState::default();
    if !incidents.is_empty() {
        state.select(Some(app.incident_scroll));
    }

    let table = Table::new(rows, [
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(16),
        Constraint::Min(18),
        Constraint::Length(24),
        Constraint::Length(8),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title)
        .style(Style::default().bg(Color::Black)))
    .row_highlight_style(Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD));

    f.render_stateful_widget(table, area, &mut state);
}

fn draw_incident_detail(f: &mut Frame, inc: &super::app::IncidentRow, area: Rect) {
    let popup_area = centered_rect(65, 60, area);
    f.render_widget(Clear, popup_area);

    let sev_color = severity_color(&inc.severity);
    let act_color = action_color(&inc.action);

    let pid_str  = inc.pid.to_string();
    let ppid_str = inc.ppid.to_string();
    let uid_str  = inc.uid.to_string();
    let sev_str  = format!("{:?}", inc.severity);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Timestamp  : ", Style::default().fg(Color::DarkGray)),
            Span::raw(inc.timestamp.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  PID        : ", Style::default().fg(Color::DarkGray)),
            Span::styled(pid_str.as_str(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  PPID       : ", Style::default().fg(Color::DarkGray)),
            Span::raw(ppid_str.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  UID        : ", Style::default().fg(Color::DarkGray)),
            Span::raw(uid_str.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  Process    : ", Style::default().fg(Color::DarkGray)),
            Span::styled(inc.process.as_str(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Event      : ", Style::default().fg(Color::DarkGray)),
            Span::raw(inc.full_kind.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  Rule       : ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if inc.rule.is_empty() { "(none)" } else { inc.rule.as_str() },
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Severity   : ", Style::default().fg(Color::DarkGray)),
            Span::styled(sev_str.as_str(), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Action     : ", Style::default().fg(Color::DarkGray)),
            Span::styled(inc.action.as_str(), Style::default().fg(act_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press Esc or Enter to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Incident Detail ")
                .border_style(Style::default().fg(Color::Red))
                .style(Style::default().bg(Color::Black)),
        );
    f.render_widget(p, popup_area);
}

// ── Config Tab ────────────────────────────────────────────────
fn draw_config(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    // Build rows
    let mut last_section = "";
    let mut rows: Vec<Row> = Vec::new();

    for (i, field) in app.config_fields.iter().enumerate() {
        // Section separator row
        if field.section != last_section {
            last_section = field.section;
            rows.push(
                Row::new(vec![
                    Cell::from(format!("[{}]", field.section))
                        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Cell::from(""),
                    Cell::from(""),
                ])
                .height(1)
                .style(Style::default().bg(Color::Black)),
            );
        }

        let is_selected = i == app.config_field_idx;
        let display_val = field.value.trim_matches('"');
        let val_color = match display_val {
            "true"  => Color::Green,
            "false" => Color::Red,
            _       => Color::Yellow,
        };

        let row = Row::new(vec![
            Cell::from(format!("  {}", field.label))
                .style(Style::default().fg(Color::White)),
            Cell::from(display_val.to_string())
                .style(Style::default().fg(val_color).add_modifier(Modifier::BOLD)),
            Cell::from(field.description)
                .style(Style::default().fg(Color::DarkGray)),
        ])
        .height(1)
        .style(if is_selected {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default().bg(Color::Black)
        });

        rows.push(row);
    }

    let save_indicator = if app.config_modified { " ● unsaved" } else { "" };
    let title = format!(" Config{} — ↑↓:select  e/Enter:edit  s:save ", save_indicator);

    let table = Table::new(rows, [
        Constraint::Length(26),
        Constraint::Length(22),
        Constraint::Min(20),
    ])
    .block(Block::default().borders(Borders::ALL).title(title)
        .border_style(if app.config_modified {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        })
        .style(Style::default().bg(Color::Black)));

    f.render_widget(table, chunks[0]);

    // Status bar
    let status = if app.config_modified {
        Paragraph::new(Span::styled(
            " s:save changes  (hot-reload will apply automatically)",
            Style::default().fg(Color::Yellow),
        ))
    } else {
        Paragraph::new(Span::styled(
            " Config saved — changes apply via hot-reload",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(status, chunks[1]);

    // Edit popup
    if app.config_editing {
        if let Some(field) = app.config_fields.get(app.config_field_idx) {
            draw_config_edit_popup(f, field.label, &app.config_edit_buf, area);
        }
    }
}

fn draw_config_edit_popup(f: &mut Frame, field_name: &str, buf: &str, area: Rect) {
    let popup_area = centered_rect(55, 20, area);
    f.render_widget(Clear, popup_area);

    let content = format!("{}_ ", buf);
    let p = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", content),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter:confirm  Esc:cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Edit: {} ", field_name))
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(p, popup_area);
}

// ── Process Tree Tab ──────────────────────────────────────────
fn draw_process_tree(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["PID", "PPID", "Process", "UID", "Events", "Last Action", "Last Seen"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let rows_data = app.process_tree_rows();
    let rows: Vec<Row> = rows_data.iter().map(|(depth, node)| {
        let indent = "  ".repeat(*depth);
        let prefix = if *depth > 0 { "└─ " } else { "" };
        let name = format!("{}{}{}", indent, prefix, node.name);

        let action_color = action_color(&node.last_action);

        Row::new(vec![
            Cell::from(node.pid.to_string()),
            Cell::from(node.ppid.to_string()),
            Cell::from(name),
            Cell::from(node.uid.to_string()),
            Cell::from(node.event_count.to_string()),
            Cell::from(Span::styled(node.last_action.as_str(), Style::default().fg(action_color))),
            Cell::from(node.last_seen.as_str()),
        ])
        .height(1)
    }).collect();

    let mut state = TableState::default();
    if !rows_data.is_empty() {
        state.select(Some(app.proc_scroll));
    }

    let title = format!(" Process Tree ({} processes) ", app.process_map.len());

    let table = Table::new(rows, [
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Min(28),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(14),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title)
        .style(Style::default().bg(Color::Black)))
    .row_highlight_style(Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD));

    f.render_stateful_widget(table, area, &mut state);
}

// ── Pending AI Proposals Tab ──────────────────────────────────
fn draw_pending(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let header = Row::new(vec!["Age", "Rule", "Action", "Description"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let rows: Vec<Row> = app.pending.iter().map(|p| {
        let action_col = action_color(&p.action);
        Row::new(vec![
            Cell::from(format_age(p.age_secs)),
            Cell::from(p.name.as_str()),
            Cell::from(Span::styled(p.action.as_str(), Style::default().fg(action_col))),
            Cell::from(p.description.as_str()),
        ]).height(1)
    }).collect();

    let title = if app.approval_store.is_none() {
        " AI Pending (approval store unavailable) ".to_string()
    } else {
        format!(" AI Pending ({}) — a:accept r:reject v/Enter:view ", app.pending.len())
    };

    let mut state = TableState::default();
    if !app.pending.is_empty() {
        state.select(Some(app.pending_scroll));
    }

    let table = Table::new(rows, [
        Constraint::Length(8),
        Constraint::Length(32),
        Constraint::Length(8),
        Constraint::Min(20),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title)
        .style(Style::default().bg(Color::Black)))
    .row_highlight_style(Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD));

    f.render_stateful_widget(table, chunks[0], &mut state);

    // Toast (recent accept/reject) takes precedence over empty-state hint.
    if let Some(msg) = app.current_toast() {
        let p = Paragraph::new(Span::styled(
            format!(" {}", msg),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ));
        f.render_widget(p, chunks[1]);
    } else if app.pending.is_empty() && app.approval_store.is_some() {
        let p = Paragraph::new(Span::styled(
            " No pending AI proposals. Enable [ai_advisor] and trigger a repeated pattern to populate.",
            Style::default().fg(Color::DarkGray),
        ));
        f.render_widget(p, chunks[1]);
    }
}

fn draw_pending_detail(f: &mut Frame, p: &super::app::PendingRow, area: Rect) {
    let popup_area = centered_rect(75, 70, area);
    f.render_widget(Clear, popup_area);

    let action_col = action_color(&p.action);
    let mut text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ID         : ", Style::default().fg(Color::DarkGray)),
            Span::raw(p.id.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  Rule       : ", Style::default().fg(Color::DarkGray)),
            Span::styled(p.name.as_str(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Action     : ", Style::default().fg(Color::DarkGray)),
            Span::styled(p.action.as_str(), Style::default().fg(action_col).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Age        : ", Style::default().fg(Color::DarkGray)),
            Span::raw(format_age(p.age_secs)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Why proposed:", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(
            format!("  {}", if p.description.is_empty() { "(none provided)" } else { p.description.as_str() }),
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(Span::styled("  TOML body:", Style::default().fg(Color::DarkGray))),
    ];
    for line in p.toml_body.lines().take(20) {
        text.push(Line::from(format!("  {}", line)));
    }
    text.push(Line::from(""));
    text.push(Line::from(Span::styled(
        "  a:accept  r:reject  Esc/Enter:close",
        Style::default().fg(Color::DarkGray),
    )));

    let popup = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" AI Proposal ")
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        );
    f.render_widget(popup, popup_area);
}

fn format_age(secs: u64) -> String {
    if secs < 60 { format!("{}s", secs) }
    else if secs < 3600 { format!("{}m", secs / 60) }
    else { format!("{}h", secs / 3600) }
}

// ── Event Detail Popup ────────────────────────────────────────
fn draw_event_detail(f: &mut Frame, ev: &super::app::EventRow, area: Rect) {
    let popup_area = centered_rect(65, 55, area);
    f.render_widget(Clear, popup_area);

    let sev_color = severity_color(&ev.severity);
    let act_color = action_color(&ev.action);

    let pid_str  = ev.pid.to_string();
    let ppid_str = ev.ppid.to_string();
    let uid_str  = ev.uid.to_string();
    let sev_str  = format!("{:?}", ev.severity);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Timestamp  : ", Style::default().fg(Color::DarkGray)),
            Span::raw(ev.timestamp.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  PID        : ", Style::default().fg(Color::DarkGray)),
            Span::styled(pid_str.as_str(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  PPID       : ", Style::default().fg(Color::DarkGray)),
            Span::raw(ppid_str.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  UID        : ", Style::default().fg(Color::DarkGray)),
            Span::raw(uid_str.as_str()),
        ]),
        Line::from(vec![
            Span::styled("  Process    : ", Style::default().fg(Color::DarkGray)),
            Span::styled(ev.process.as_str(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Event      : ", Style::default().fg(Color::DarkGray)),
            Span::raw(ev.full_kind.as_str()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Severity   : ", Style::default().fg(Color::DarkGray)),
            Span::styled(sev_str.as_str(), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Action     : ", Style::default().fg(Color::DarkGray)),
            Span::styled(ev.action.as_str(), Style::default().fg(act_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Press Esc or Enter to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Event Detail ")
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        );
    f.render_widget(p, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

// ── Footer ────────────────────────────────────────────────────
fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let text = if app.is_detail_open() {
        Line::from(vec![
            Span::styled(" Esc/Enter", Style::default().fg(Color::Yellow)),
            Span::raw(":close popup"),
        ])
    } else if app.input_mode == InputMode::Filtering {
        Line::from(vec![
            Span::styled(" Enter", Style::default().fg(Color::Yellow)),
            Span::raw(":apply  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(":cancel"),
        ])
    } else if app.active_tab == Tab::Config {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Yellow)),
            Span::raw(":quit  "),
            Span::styled("Tab/1-5", Style::default().fg(Color::Yellow)),
            Span::raw(":switch  "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(":select  "),
            Span::styled("e/Enter", Style::default().fg(Color::Yellow)),
            Span::raw(":edit  "),
            Span::styled("s", Style::default().fg(Color::Yellow)),
            Span::raw(":save"),
        ])
    } else if app.active_tab == Tab::Incidents {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Yellow)),
            Span::raw(":quit  "),
            Span::styled("Tab/1-6", Style::default().fg(Color::Yellow)),
            Span::raw(":switch  "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(":scroll  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(":detail  "),
            Span::styled("f", Style::default().fg(Color::Yellow)),
            Span::raw(":filter(All/Blocked/Alerted)"),
        ])
    } else if app.active_tab == Tab::Pending {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Yellow)),
            Span::raw(":quit  "),
            Span::styled("Tab/1-6", Style::default().fg(Color::Yellow)),
            Span::raw(":switch  "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(":scroll  "),
            Span::styled("a", Style::default().fg(Color::Green)),
            Span::raw(":accept  "),
            Span::styled("r", Style::default().fg(Color::Red)),
            Span::raw(":reject  "),
            Span::styled("v/Enter", Style::default().fg(Color::Yellow)),
            Span::raw(":view"),
        ])
    } else {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Yellow)),
            Span::raw(":quit  "),
            Span::styled("Tab/1-6", Style::default().fg(Color::Yellow)),
            Span::raw(":switch  "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(":scroll  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(":detail  "),
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::raw(":filter"),
        ])
    };
    f.render_widget(
        Paragraph::new(text).style(Style::default().bg(Color::Black)),
        area,
    );
}

// ── Helpers ───────────────────────────────────────────────────
fn severity_color(s: &Severity) -> Color {
    match s {
        Severity::Info     => Color::White,
        Severity::Low      => Color::Green,
        Severity::Medium   => Color::Yellow,
        Severity::High     => Color::Red,
        Severity::Critical => Color::Magenta,
    }
}

fn action_color(action: &str) -> Color {
    match action {
        a if a.contains("Block") || a.contains("Kill") => Color::Red,
        a if a.contains("Alert")                       => Color::Yellow,
        _                                              => Color::Green,
    }
}
