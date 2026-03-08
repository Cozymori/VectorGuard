use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap},
};

use super::app::{App, Tab};
use crate::event::Severity;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // 전체 레이아웃: 헤더(탭) / 본문 / 푸터
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // 탭 바
            Constraint::Min(0),     // 본문
            Constraint::Length(1),  // 푸터
        ])
        .split(area);

    draw_tabs(f, app, chunks[0]);

    match app.active_tab {
        Tab::Dashboard => draw_dashboard(f, app, chunks[1]),
        Tab::Events    => draw_events(f, app, chunks[1]),
        Tab::Config    => draw_config(f, app, chunks[1]),
    }

    draw_footer(f, chunks[2]);
}

// ── 탭 바 ─────────────────────────────────────────────────────
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

    // 통계 카드 4개
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
    draw_stat_card(f, "Total Events",  &s.total_events.to_string(),  Color::White,  stat_chunks[0]);
    draw_stat_card(f, "Blocked",       &s.blocked.to_string(),        Color::Red,    stat_chunks[1]);
    draw_stat_card(f, "Alerts",        &s.alerts.to_string(),         Color::Yellow, stat_chunks[2]);
    draw_stat_card(f, "High Severity", &s.high_severity.to_string(),  Color::Magenta,stat_chunks[3]);

    // 최근 이벤트 미니 테이블
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
    .block(Block::default().borders(Borders::ALL).title(format!(" {} ", title)));
    f.render_widget(text, area);
}

fn draw_recent_events(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Time", "PID", "Process", "Kind", "Severity", "Action"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let recent: Vec<Row> = app.events.iter().rev().take(20).map(|e| {
        let sev_color = severity_color(&e.severity);
        Row::new(vec![
            Cell::from(e.timestamp.as_str()),
            Cell::from(e.pid.to_string()),
            Cell::from(e.process.as_str()),
            Cell::from(e.kind.as_str()),
            Cell::from(Span::styled(format!("{:?}", e.severity), Style::default().fg(sev_color))),
            Cell::from(e.action.as_str()),
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
    .block(Block::default().borders(Borders::ALL).title(" Recent Events "))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);
}

// ── Events 탭 ─────────────────────────────────────────────────
fn draw_events(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Time", "PID", "Process", "Kind", "Severity", "Action"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let rows: Vec<Row> = app.events.iter().map(|e| {
        let sev_color = severity_color(&e.severity);
        Row::new(vec![
            Cell::from(e.timestamp.as_str()),
            Cell::from(e.pid.to_string()),
            Cell::from(e.process.as_str()),
            Cell::from(e.kind.as_str()),
            Cell::from(Span::styled(format!("{:?}", e.severity), Style::default().fg(sev_color))),
            Cell::from(e.action.as_str()),
        ])
        .height(1)
    }).collect();

    let mut state = TableState::default();
    state.select(Some(app.event_scroll));

    let table = Table::new(rows, [
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(16),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(8),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" All Events (↑↓ to scroll) "))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, area, &mut state);
}

// ── Config 탭 ─────────────────────────────────────────────────
fn draw_config(f: &mut Frame, app: &App, area: Rect) {
    let p = Paragraph::new(app.config_text.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" config.toml (read-only — edit with: vi config.toml) "),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

// ── 푸터 ──────────────────────────────────────────────────────
fn draw_footer(f: &mut Frame, area: Rect) {
    let text = Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit  "),
        Span::styled("Tab/1-3", Style::default().fg(Color::Yellow)),
        Span::raw(":switch  "),
        Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
        Span::raw(":scroll"),
    ]);
    f.render_widget(Paragraph::new(text), area);
}

// ── 헬퍼 ──────────────────────────────────────────────────────
fn severity_color(s: &Severity) -> Color {
    match s {
        Severity::Info     => Color::White,
        Severity::Low      => Color::Green,
        Severity::Medium   => Color::Yellow,
        Severity::High     => Color::Red,
        Severity::Critical => Color::Magenta,
    }
}
