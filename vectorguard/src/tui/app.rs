use std::collections::HashMap;
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
    ProcessTree,
}

impl Tab {
    pub fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Events", "Config", "Process Tree"]
    }

    pub fn index(&self) -> usize {
        match self {
            Tab::Dashboard   => 0,
            Tab::Events      => 1,
            Tab::Config      => 2,
            Tab::ProcessTree => 3,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            1 => Tab::Events,
            2 => Tab::Config,
            3 => Tab::ProcessTree,
            _ => Tab::Dashboard,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Filtering,
}

/// Overall TUI state
pub struct App {
    pub state:         AppState,
    pub active_tab:    Tab,

    // Dashboard
    pub stats:         Stats,

    // Events tab
    pub events:        Vec<EventRow>,
    pub event_scroll:  usize,

    // Event detail popup
    pub selected_event: Option<usize>,

    // Filter
    pub input_mode:    InputMode,
    pub filter_input:  String,
    pub filter_query:  String,

    // Process Tree tab
    pub process_map:   HashMap<u32, ProcessNode>,
    pub proc_scroll:   usize,

    // Config tab
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
    pub ppid:      u32,
    pub uid:       u32,
    pub process:   String,
    pub kind:      String,
    pub severity:  Severity,
    pub action:    String,
    pub full_kind: String,
}

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid:         u32,
    pub ppid:        u32,
    pub name:        String,
    pub uid:         u32,
    pub event_count: u64,
    pub last_action: String,
    pub last_seen:   String,
}

impl App {
    pub fn new(config_text: String) -> Self {
        Self {
            state:          AppState::Running,
            active_tab:     Tab::Dashboard,
            stats:          Stats::default(),
            events:         Vec::new(),
            event_scroll:   0,
            selected_event: None,
            input_mode:     InputMode::Normal,
            filter_input:   String::new(),
            filter_query:   String::new(),
            process_map:    HashMap::new(),
            proc_scroll:    0,
            config_text,
        }
    }

    pub fn next_tab(&mut self) {
        let next = (self.active_tab.index() + 1) % Tab::titles().len();
        self.active_tab = Tab::from_index(next);
    }

    pub fn scroll_up(&mut self) {
        match self.active_tab {
            Tab::ProcessTree => { self.proc_scroll = self.proc_scroll.saturating_sub(1); }
            _ => { self.event_scroll = self.event_scroll.saturating_sub(1); }
        }
    }

    pub fn scroll_down(&mut self) {
        match self.active_tab {
            Tab::ProcessTree => {
                if self.proc_scroll + 1 < self.process_map.len() {
                    self.proc_scroll += 1;
                }
            }
            _ => {
                let len = self.filtered_events().len();
                if self.event_scroll + 1 < len {
                    self.event_scroll += 1;
                }
            }
        }
    }

    pub fn open_detail(&mut self) {
        let len = self.filtered_events().len();
        if len > 0 {
            self.selected_event = Some(self.event_scroll);
        }
    }

    pub fn close_detail(&mut self) {
        self.selected_event = None;
    }

    pub fn is_detail_open(&self) -> bool {
        self.selected_event.is_some()
    }

    pub fn filtered_events(&self) -> Vec<&EventRow> {
        let q = self.filter_query.to_lowercase();
        if q.is_empty() {
            return self.events.iter().collect();
        }
        self.events.iter().filter(|e| {
            e.process.to_lowercase().contains(&q)
                || e.kind.to_lowercase().contains(&q)
                || e.action.to_lowercase().contains(&q)
                || e.full_kind.to_lowercase().contains(&q)
        }).collect()
    }

    pub fn process_tree_rows(&self) -> Vec<(usize, &ProcessNode)> {
        fn dfs<'a>(
            pid: u32,
            depth: usize,
            map: &'a HashMap<u32, ProcessNode>,
            result: &mut Vec<(usize, u32)>,
            visited: &mut std::collections::HashSet<u32>,
        ) {
            if !visited.insert(pid) { return; }
            result.push((depth, pid));
            let mut children: Vec<u32> = map.values()
                .filter(|n| n.ppid == pid && n.pid != pid)
                .map(|n| n.pid)
                .collect();
            children.sort();
            for child_pid in children {
                dfs(child_pid, depth + 1, map, result, visited);
            }
        }

        let mut roots: Vec<u32> = self.process_map.values()
            .filter(|n| n.ppid == 0 || !self.process_map.contains_key(&n.ppid))
            .map(|n| n.pid)
            .collect();
        roots.sort();

        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        for root_pid in roots {
            dfs(root_pid, 0, &self.process_map, &mut order, &mut visited);
        }

        order.into_iter()
            .filter_map(|(depth, pid)| self.process_map.get(&pid).map(|n| (depth, n)))
            .collect()
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

        let full_kind = match &ev.event_type {
            crate::event::EventType::Exec                    => "Exec".to_string(),
            crate::event::EventType::FileAccess { path, .. } => format!("File:{}", path),
            crate::event::EventType::Network { port, .. }    => format!("Net:{}", port),
            crate::event::EventType::Privilege { syscall, .. } => format!("Priv:{}", syscall),
            crate::event::EventType::Signal { signum, .. }   => format!("Sig:{}", signum),
        };

        // Truncated kind for table display
        let kind = if full_kind.len() > 40 {
            format!("{}…", &full_kind[..39])
        } else {
            full_kind.clone()
        };

        let action_str = format!("{:?}", ev.action);

        self.events.push(EventRow {
            timestamp: format_ts(ev.timestamp),
            pid:       ev.process.pid,
            ppid:      ev.process.ppid,
            uid:       ev.process.uid,
            process:   ev.process.binary.clone(),
            kind,
            severity:  ev.severity.clone(),
            action:    action_str.clone(),
            full_kind,
        });

        if self.events.len() > 500 {
            self.events.remove(0);
        }

        // Update process map
        let entry = self.process_map.entry(ev.process.pid).or_insert(ProcessNode {
            pid:         ev.process.pid,
            ppid:        ev.process.ppid,
            name:        ev.process.binary.clone(),
            uid:         ev.process.uid,
            event_count: 0,
            last_action: String::new(),
            last_seen:   String::new(),
        });
        entry.event_count += 1;
        entry.last_action = action_str;
        entry.last_seen = format_ts(ev.timestamp);
    }
}

fn format_ts(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let ms   = (ns % 1_000_000_000) / 1_000_000;
    format!("{}.{:03}", secs, ms)
}
