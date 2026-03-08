use serde::{Deserialize, Serialize};
use std::fs;

use crate::event::{Action, EventType, NormalizedEvent};

/// Top-level structure of a rule file (.toml)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RuleSet {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name:   String,
    pub action: RuleAction,

    // Conditions — all configured conditions must match (AND logic)
    /// Glob pattern for process binary name (e.g. "nginx", "py*")
    #[serde(default)]
    pub match_process: Vec<String>,

    /// Path prefix for FileAccess events (e.g. "/etc/shadow")
    #[serde(default)]
    pub match_path_prefix: Vec<String>,

    /// Executable path prefix for Exec events (e.g. "/bin/sh")
    #[serde(default)]
    pub match_exec_path: Vec<String>,

    /// Destination port for Network events
    #[serde(default)]
    pub match_port: Vec<u16>,

    /// UID match (0 = root)
    pub match_uid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Alert,
    Log,
    Allow,
}

impl RuleAction {
    pub fn to_action(&self) -> Action {
        match self {
            RuleAction::Block          => Action::Blocked,
            RuleAction::Alert          => Action::Alerted,
            RuleAction::Log            => Action::Allowed,
            RuleAction::Allow          => Action::Allowed,
        }
    }
}

impl RuleSet {
    /// Load all *.toml files from the rules_path directory
    /// Falls back to built-in default rules if no files are found
    pub fn load_dir(path: &str) -> Self {
        let mut all_rules: Vec<Rule> = Vec::new();

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("toml") {
                    if let Ok(content) = fs::read_to_string(&p) {
                        match toml::from_str::<RuleSet>(&content) {
                            Ok(rs) => all_rules.extend(rs.rules),
                            Err(e) => tracing::warn!("Failed to parse rule file {:?}: {}", p, e),
                        }
                    }
                }
            }
        }

        if all_rules.is_empty() {
            all_rules = Self::builtin_rules();
        }

        RuleSet { rules: all_rules }
    }

    /// Return the Action of the first matching rule, or None if no rule matches
    pub fn evaluate(&self, event: &NormalizedEvent) -> Option<Action> {
        self.rules
            .iter()
            .find(|r| r.matches(event))
            .map(|r| r.action.to_action())
    }

    fn builtin_rules() -> Vec<Rule> {
        vec![
            Rule {
                name:              "block-shadow-access".into(),
                action:            RuleAction::Block,
                match_process:     vec![],
                match_path_prefix: vec![
                    "/etc/shadow".into(),
                    "/etc/sudoers".into(),
                    "/etc/gshadow".into(),
                ],
                match_exec_path:   vec![],
                match_port:        vec![],
                match_uid:         None,
            },
            Rule {
                name:              "alert-shell-exec-by-service".into(),
                action:            RuleAction::Alert,
                match_process:     vec!["nginx".into(), "postgres".into(), "apache2".into()],
                match_path_prefix: vec![],
                match_exec_path:   vec![
                    "/bin/sh".into(),
                    "/bin/bash".into(),
                    "/bin/dash".into(),
                    "/usr/bin/python".into(),
                    "/usr/bin/perl".into(),
                ],
                match_port:        vec![],
                match_uid:         None,
            },
            Rule {
                name:              "alert-outbound-unusual-port".into(),
                action:            RuleAction::Alert,
                match_process:     vec![],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![4444, 1337, 31337, 9001, 8888],
                match_uid:         None,
            },
            Rule {
                name:              "alert-root-exec".into(),
                action:            RuleAction::Alert,
                match_process:     vec![],
                match_path_prefix: vec![],
                match_exec_path:   vec!["/usr/bin/wget".into(), "/usr/bin/curl".into(), "/usr/bin/nc".into()],
                match_port:        vec![],
                match_uid:         Some(0),
            },
        ]
    }
}

impl Rule {
    fn matches(&self, event: &NormalizedEvent) -> bool {
        // Process name glob filter
        if !self.match_process.is_empty() {
            let binary = &event.process.binary;
            let hit = self.match_process.iter().any(|pat| {
                glob::Pattern::new(pat)
                    .map(|p| p.matches(binary))
                    .unwrap_or(false)
            });
            if !hit {
                return false;
            }
        }

        // UID filter
        if let Some(uid) = self.match_uid {
            if event.process.uid != uid {
                return false;
            }
        }

        // Port filter (Network events only)
        if !self.match_port.is_empty() {
            match &event.event_type {
                EventType::Network { port, .. } => {
                    if !self.match_port.contains(port) {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // File path prefix filter (FileAccess events only)
        if !self.match_path_prefix.is_empty() {
            match &event.event_type {
                EventType::FileAccess { path, .. } => {
                    let hit = self.match_path_prefix.iter().any(|p| path.starts_with(p.as_str()));
                    if !hit {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // Exec path prefix filter (Exec events only)
        if !self.match_exec_path.is_empty() {
            match &event.event_type {
                EventType::Exec => {
                    let binary = &event.process.binary;
                    let hit = self.match_exec_path.iter().any(|p| binary.starts_with(p.as_str()));
                    if !hit {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        true
    }
}
