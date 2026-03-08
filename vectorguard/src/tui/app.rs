use crate::event::{NormalizedEvent, Severity};

#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    Running,
    Quit,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Dashboard,
    Events,
    Config,
}

impl Tab {
    pub fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Events", "Config"]
    }

    pub fn index(&self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Events    => 1,
            Tab::Config    => 2,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            1 => Tab::Events,
            2 => Tab::Config,
            _ => Tab::Dashboard,
        }
    }
}

/// Overall TUI state
pub struct App {
    pub state:         AppState,
    pub active_tab:    Tab,

    // Dashboard
    pub stats:         Stats,

    // Events tab — recent event list
    pub events:        Vec<EventRow>,
    pub event_scroll:  usize,

    // Config tab — config viewer (read-only; edit with vi)
    pub config_text:   String,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub total_events:   u64,
    pub blocked:        u64,
    pub alerts:         u64,
    pub high_severity:  u64,
}

#[derive(Debug, Clone)]
pub struct EventRow {
    pub timestamp: String,
    pub pid:       u32,
    pub process:   String,
    pub kind:      String,
    pub severity:  Severity,
    pub action:    String,
}

impl App {
    pub fn new(config_text: String) -> Self {
        Self {
            state:        AppState::Running,
            active_tab:   Tab::Dashboard,
            stats:        Stats::default(),
            events:       Vec::new(),
            event_scroll: 0,
            config_text,
        }
    }

    pub fn next_tab(&mut self) {
        let next = (self.active_tab.index() + 1) % Tab::titles().len();
        self.active_tab = Tab::from_index(next);
    }

    pub fn scroll_up(&mut self) {
        self.event_scroll = self.event_scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        if self.event_scroll + 1 < self.events.len() {
            self.event_scroll += 1;
        }
    }

    /// Called when a new event is received (keeps at most 500 events)
    pub fn push_event(&mut self, ev: &NormalizedEvent) {
        self.stats.total_events += 1;

        match ev.severity {
            Severity::High | Severity::Critical => self.stats.high_severity += 1,
            _ => {}
        }

        use crate::event::Action;
        match ev.action {
            Action::Blocked | Action::Killed => self.stats.blocked += 1,
            Action::Alerted                  => self.stats.alerts += 1,
            _ => {}
        }

        let kind = match &ev.event_type {
            crate::event::EventType::Exec                   => "Exec".to_string(),
            crate::event::EventType::FileAccess { path, .. } => format!("File:{}", path),
            crate::event::EventType::Network { port, .. }   => format!("Net:{}", port),
            crate::event::EventType::Privilege { syscall, .. } => format!("Priv:{}", syscall),
            crate::event::EventType::Signal { signum, .. }  => format!("Sig:{}", signum),
        };

        self.events.push(EventRow {
            timestamp: format_ts(ev.timestamp),
            pid:       ev.process.pid,
            process:   ev.process.binary.clone(),
            kind,
            severity:  ev.severity.clone(),
            action:    format!("{:?}", ev.action),
        });

        if self.events.len() > 500 {
            self.events.remove(0);
        }
    }
}

fn format_ts(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let ms   = (ns % 1_000_000_000) / 1_000_000;
    format!("{}.{:03}", secs, ms)
}
