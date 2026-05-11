use std::collections::HashMap;
use crate::event::{NormalizedEvent, Severity};

#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    Running,
    Quit,
}

// ── Config Editor ─────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq)]
pub enum FieldType { Str, Bool, Int, Float }

#[derive(Debug, Clone)]
pub struct ConfigField {
    pub section:     &'static str,
    pub label:       &'static str,
    pub toml_key:    &'static str,
    pub description: &'static str,
    pub value:       String,   // raw TOML value (e.g. `"info"`, `true`, `3`)
    pub field_type:  FieldType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Dashboard,
    Events,
    Incidents,
    Config,
    ProcessTree,
}

impl Tab {
    pub fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Events", "Incidents", "Config", "Process Tree"]
    }

    pub fn index(&self) -> usize {
        match self {
            Tab::Dashboard   => 0,
            Tab::Events      => 1,
            Tab::Incidents   => 2,
            Tab::Config      => 3,
            Tab::ProcessTree => 4,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            1 => Tab::Events,
            2 => Tab::Incidents,
            3 => Tab::Config,
            4 => Tab::ProcessTree,
            _ => Tab::Dashboard,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IncidentFilter {
    All,
    Blocked,
    Alerted,
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

    // Incidents tab
    pub incidents:         Vec<IncidentRow>,
    pub incident_scroll:   usize,
    pub incident_filter:   IncidentFilter,
    pub selected_incident: Option<usize>,

    // Process Tree tab
    pub process_map:   HashMap<u32, ProcessNode>,
    pub proc_scroll:   usize,

    // Config tab
    pub config_text:     String,
    pub config_path:     String,
    pub config_fields:   Vec<ConfigField>,
    pub config_field_idx: usize,
    pub config_editing:  bool,
    pub config_edit_buf: String,
    pub config_modified: bool,
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
pub struct IncidentRow {
    pub timestamp: String,
    pub pid:       u32,
    pub ppid:      u32,
    pub uid:       u32,
    pub process:   String,
    pub kind:      String,
    pub full_kind: String,
    pub severity:  Severity,
    pub action:    String,
    pub rule:      String,
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
    pub fn new(config_text: String, config_path: String) -> Self {
        let fields = build_config_fields(&config_text);
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
            incidents:          Vec::new(),
            incident_scroll:    0,
            incident_filter:    IncidentFilter::All,
            selected_incident:  None,
            process_map:    HashMap::new(),
            proc_scroll:    0,
            config_text,
            config_path,
            config_fields:   fields,
            config_field_idx: 0,
            config_editing:  false,
            config_edit_buf: String::new(),
            config_modified: false,
        }
    }

    // ── Config Editor ─────────────────────────────────────────
    pub fn start_config_edit(&mut self) {
        if let Some(field) = self.config_fields.get(self.config_field_idx) {
            // Strip surrounding quotes for easier editing
            self.config_edit_buf = field.value.trim_matches('"').to_string();
            self.config_editing = true;
        }
    }

    pub fn cancel_config_edit(&mut self) {
        self.config_editing = false;
        self.config_edit_buf.clear();
    }

    pub fn confirm_config_edit(&mut self) {
        let idx = self.config_field_idx;
        if let Some(field) = self.config_fields.get_mut(idx) {
            let raw = match field.field_type {
                FieldType::Str => format!("\"{}\"", self.config_edit_buf.trim()),
                _              => self.config_edit_buf.trim().to_string(),
            };
            // Update config_text
            self.config_text = update_toml_value(
                &self.config_text, field.section, field.toml_key, &raw,
            );
            field.value = raw;
            self.config_modified = true;
        }
        self.config_editing = false;
        self.config_edit_buf.clear();
    }

    pub fn save_config(&mut self) {
        match std::fs::write(&self.config_path, &self.config_text) {
            Ok(_)  => self.config_modified = false,
            Err(e) => tracing::warn!("Failed to save config: {}", e),
        }
    }

    pub fn scroll_config_up(&mut self) {
        self.config_field_idx = self.config_field_idx.saturating_sub(1);
    }

    pub fn scroll_config_down(&mut self) {
        if self.config_field_idx + 1 < self.config_fields.len() {
            self.config_field_idx += 1;
        }
    }

    pub fn next_tab(&mut self) {
        let next = (self.active_tab.index() + 1) % Tab::titles().len();
        self.active_tab = Tab::from_index(next);
    }

    pub fn scroll_up(&mut self) {
        match self.active_tab {
            Tab::ProcessTree => { self.proc_scroll = self.proc_scroll.saturating_sub(1); }
            Tab::Incidents   => { self.incident_scroll = self.incident_scroll.saturating_sub(1); }
            Tab::Config      => { self.scroll_config_up(); }
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
            Tab::Incidents => {
                let len = self.filtered_incidents().len();
                if self.incident_scroll + 1 < len {
                    self.incident_scroll += 1;
                }
            }
            Tab::Config => { self.scroll_config_down(); }
            _ => {
                let len = self.filtered_events().len();
                if self.event_scroll + 1 < len {
                    self.event_scroll += 1;
                }
            }
        }
    }

    pub fn open_detail(&mut self) {
        match self.active_tab {
            Tab::Incidents => {
                let len = self.filtered_incidents().len();
                if len > 0 {
                    self.selected_incident = Some(self.incident_scroll);
                }
            }
            _ => {
                let len = self.filtered_events().len();
                if len > 0 {
                    self.selected_event = Some(self.event_scroll);
                }
            }
        }
    }

    pub fn close_detail(&mut self) {
        self.selected_event = None;
        self.selected_incident = None;
    }

    pub fn is_detail_open(&self) -> bool {
        self.selected_event.is_some() || self.selected_incident.is_some()
    }

    pub fn cycle_incident_filter(&mut self) {
        self.incident_filter = match self.incident_filter {
            IncidentFilter::All     => IncidentFilter::Blocked,
            IncidentFilter::Blocked => IncidentFilter::Alerted,
            IncidentFilter::Alerted => IncidentFilter::All,
        };
        self.incident_scroll = 0;
    }

    pub fn filtered_incidents(&self) -> Vec<&IncidentRow> {
        self.incidents.iter().filter(|i| {
            match self.incident_filter {
                IncidentFilter::All     => true,
                IncidentFilter::Blocked => i.action.contains("Block") || i.action.contains("Kill"),
                IncidentFilter::Alerted => i.action.contains("Alert"),
            }
        }).collect()
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

        // Track incidents (Blocked / Alerted / Killed) — before events push to avoid move
        if matches!(ev.action, Action::Blocked | Action::Alerted | Action::Killed) {
            self.incidents.push(IncidentRow {
                timestamp: format_ts(ev.timestamp),
                pid:       ev.process.pid,
                ppid:      ev.process.ppid,
                uid:       ev.process.uid,
                process:   ev.process.binary.clone(),
                kind:      kind.clone(),
                full_kind: full_kind.clone(),
                severity:  ev.severity.clone(),
                action:    action_str.clone(),
                rule:      ev.rule_name.clone().unwrap_or_default(),
            });
            if self.incidents.len() > 500 {
                self.incidents.remove(0);
            }
        }

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

// ── Config Editor Helpers ─────────────────────────────────────

fn build_config_fields(text: &str) -> Vec<ConfigField> {
    let mut fields = vec![
        ConfigField { section: "system",     label: "log_level",            toml_key: "log_level",            description: "debug / info / warn / error",      field_type: FieldType::Str,   value: String::new() },
        ConfigField { section: "fast_path",  label: "enabled",              toml_key: "enabled",              description: "Enable rule engine",               field_type: FieldType::Bool,  value: String::new() },
        ConfigField { section: "fast_path",  label: "default_action",       toml_key: "default_action",       description: "block / alert / log",              field_type: FieldType::Str,   value: String::new() },
        ConfigField { section: "slow_path",  label: "enabled",              toml_key: "enabled",              description: "Enable anomaly detection",         field_type: FieldType::Bool,  value: String::new() },
        ConfigField { section: "slow_path",  label: "similarity_threshold", toml_key: "similarity_threshold", description: "Vector similarity threshold 0-1",  field_type: FieldType::Float, value: String::new() },
        ConfigField { section: "ai_advisor", label: "enabled",              toml_key: "enabled",              description: "Enable AI rule generation",        field_type: FieldType::Bool,  value: String::new() },
        ConfigField { section: "ai_advisor", label: "provider",             toml_key: "provider",             description: "anthropic / openai",               field_type: FieldType::Str,   value: String::new() },
        ConfigField { section: "ai_advisor", label: "api_key_env",          toml_key: "api_key_env",          description: "Env var holding API key",          field_type: FieldType::Str,   value: String::new() },
        ConfigField { section: "ai_advisor", label: "model",                toml_key: "model",                description: "Model name (e.g. claude-sonnet-4-6)", field_type: FieldType::Str,   value: String::new() },
        ConfigField { section: "ai_advisor", label: "trigger_threshold",    toml_key: "trigger_threshold",    description: "Pattern count to trigger AI call", field_type: FieldType::Int,   value: String::new() },
        ConfigField { section: "tui",        label: "refresh_rate_ms",      toml_key: "refresh_rate_ms",      description: "TUI refresh rate in ms",           field_type: FieldType::Int,   value: String::new() },
        ConfigField { section: "tui",        label: "theme",                toml_key: "theme",                description: "dark / light",                     field_type: FieldType::Str,   value: String::new() },
    ];
    for f in &mut fields {
        f.value = extract_toml_value(text, f.section, f.toml_key);
    }
    fields
}

/// Extract the raw TOML value for `key` inside `section` (e.g. `"info"` or `true`).
fn extract_toml_value(text: &str, section: &str, key: &str) -> String {
    let target = format!("[{}]", section);
    let mut in_section = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            in_section = trimmed == target;
            continue;
        }
        if !in_section { continue; }

        let code = trimmed.split('#').next().unwrap_or("").trim();
        if let Some(eq) = code.find('=') {
            if code[..eq].trim() == key {
                return code[eq + 1..].trim().to_string();
            }
        }
    }
    String::new()
}

/// Replace the value of `key` inside `section` in `text`.
pub fn update_toml_value(text: &str, section: &str, key: &str, new_val: &str) -> String {
    let target = format!("[{}]", section);
    let mut in_section = false;
    let mut replaced = false;

    text.lines().map(|line| {
        let trimmed = line.trim();

        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            in_section = trimmed == target;
            return line.to_string();
        }

        if in_section && !replaced {
            let code = trimmed.split('#').next().unwrap_or("").trim();
            if let Some(eq) = code.find('=') {
                if code[..eq].trim() == key {
                    let indent_len = line.len() - line.trim_start().len();
                    let indent = &line[..indent_len];
                    replaced = true;
                    return format!("{}{} = {}", indent, key, new_val);
                }
            }
        }

        line.to_string()
    }).collect::<Vec<_>>().join("\n")
}
