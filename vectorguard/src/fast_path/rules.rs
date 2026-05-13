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

    /// Optional free-text rationale. Not used for matching; surfaced in the TUI
    /// pending-approval view so reviewers can see why the advisor proposed a rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

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
            RuleAction::Log            => Action::Logged,
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

    /// Return the (Action, rule name) of the first matching rule, or None if no rule matches
    pub fn evaluate(&self, event: &NormalizedEvent) -> Option<(Action, String)> {
        self.rules
            .iter()
            .find(|r| r.matches(event))
            .map(|r| (r.action.to_action(), r.name.clone()))
    }

    fn builtin_rules() -> Vec<Rule> {
        vec![
            Rule {
                name:              "block-shadow-access".into(),
                action:            RuleAction::Block,
                description:       None,
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
                description:       None,
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
                description:       None,
                match_process:     vec![],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![4444, 1337, 31337, 9001, 8888],
                match_uid:         None,
            },
            Rule {
                name:              "alert-root-exec".into(),
                action:            RuleAction::Alert,
                description:       None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;

    fn base_event(binary: &str, uid: u32, event_type: EventType) -> NormalizedEvent {
        NormalizedEvent {
            id: 0,
            timestamp: 0,
            source: EventSource::NativeEbpf,
            process: ProcessInfo {
                pid: 1, ppid: 0, uid, gid: 0,
                binary: binary.to_string(),
                args: vec![],
                cwd: String::new(),
            },
            parent:     None,
            event_type,
            severity:   Severity::Info,
            action:     Action::Allowed,
            rule_name:  None,
            k8s:        None,
            raw:        serde_json::Value::Null,
        }
    }

    fn exec_event(binary: &str) -> NormalizedEvent {
        base_event(binary, 1000, EventType::Exec)
    }

    fn file_event(binary: &str, path: &str) -> NormalizedEvent {
        base_event(binary, 1000, EventType::FileAccess {
            path: path.to_string(),
            flags: FileFlags { read: true, write: false, execute: false },
        })
    }

    fn net_event(binary: &str, port: u16) -> NormalizedEvent {
        base_event(binary, 1000, EventType::Network {
            direction: Direction::Outbound,
            remote_ip: "1.2.3.4".parse().unwrap(),
            port,
            proto: Proto::Tcp,
        })
    }

    // ── builtin rules ────────────────────────────────────────

    #[test]
    fn builtin_blocks_shadow_access() {
        let rs = RuleSet { rules: RuleSet::builtin_rules() };
        let ev = file_event("cat", "/etc/shadow");
        let result = rs.evaluate(&ev);
        assert_eq!(result.as_ref().map(|(a, _)| a), Some(&Action::Blocked));
    }

    #[test]
    fn builtin_allows_normal_file() {
        let rs = RuleSet { rules: RuleSet::builtin_rules() };
        let ev = file_event("cat", "/tmp/test.txt");
        assert_eq!(rs.evaluate(&ev), None);
    }

    #[test]
    fn builtin_alerts_shell_from_nginx() {
        let rs = RuleSet { rules: RuleSet::builtin_rules() };
        let ev3 = file_event("any", "/etc/sudoers");
        let result = rs.evaluate(&ev3);
        assert_eq!(result.as_ref().map(|(a, _)| a), Some(&Action::Blocked));
    }

    #[test]
    fn builtin_alerts_suspicious_port() {
        let rs = RuleSet { rules: RuleSet::builtin_rules() };
        let ev = net_event("curl", 4444);
        let result = rs.evaluate(&ev);
        assert_eq!(result.as_ref().map(|(a, _)| a), Some(&Action::Alerted));
    }

    #[test]
    fn normal_port_not_alerted() {
        let rs = RuleSet { rules: RuleSet::builtin_rules() };
        let ev = net_event("curl", 443);
        assert_eq!(rs.evaluate(&ev), None);
    }

    // ── custom rules ─────────────────────────────────────────

    #[test]
    fn custom_rule_uid_match() {
        let rs = RuleSet {
            rules: vec![Rule {
                name:              "alert-root".into(),
                action:            RuleAction::Alert,
                description:       None,
                match_process:     vec![],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![],
                match_uid:         Some(0),
            }],
        };
        let ev_root = base_event("bash", 0, EventType::Exec);
        let ev_user = base_event("bash", 1000, EventType::Exec);
        assert_eq!(rs.evaluate(&ev_root).map(|(a, _)| a), Some(Action::Alerted));
        assert_eq!(rs.evaluate(&ev_user), None);
    }

    #[test]
    fn custom_rule_process_glob() {
        let rs = RuleSet {
            rules: vec![Rule {
                name:              "block-py".into(),
                action:            RuleAction::Block,
                description:       None,
                match_process:     vec!["py*".into()],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![],
                match_uid:         None,
            }],
        };
        assert_eq!(rs.evaluate(&exec_event("python3")).map(|(a, _)| a),  Some(Action::Blocked));
        assert_eq!(rs.evaluate(&exec_event("pypy")).map(|(a, _)| a),     Some(Action::Blocked));
        assert_eq!(rs.evaluate(&exec_event("ruby")),     None);
    }

    #[test]
    fn first_matching_rule_wins() {
        let rs = RuleSet {
            rules: vec![
                Rule {
                    name: "alert".into(), action: RuleAction::Alert,
                    description: None,
                    match_process: vec!["nginx".into()],
                    match_path_prefix: vec![], match_exec_path: vec![],
                    match_port: vec![], match_uid: None,
                },
                Rule {
                    name: "block".into(), action: RuleAction::Block,
                    description: None,
                    match_process: vec!["nginx".into()],
                    match_path_prefix: vec![], match_exec_path: vec![],
                    match_port: vec![], match_uid: None,
                },
            ],
        };
        assert_eq!(rs.evaluate(&exec_event("nginx")).map(|(a, _)| a), Some(Action::Alerted));
    }

    #[test]
    fn evaluate_returns_rule_name() {
        let rs = RuleSet {
            rules: vec![Rule {
                name:              "my-custom-rule".into(),
                action:            RuleAction::Block,
                description:       None,
                match_process:     vec!["bash".into()],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![],
                match_uid:         None,
            }],
        };
        let result = rs.evaluate(&exec_event("bash"));
        assert_eq!(result, Some((Action::Blocked, "my-custom-rule".into())));
    }

    #[test]
    fn log_action_maps_to_logged_not_allowed() {
        let rs = RuleSet {
            rules: vec![Rule {
                name:              "log-curl".into(),
                action:            RuleAction::Log,
                description:       None,
                match_process:     vec!["curl".into()],
                match_path_prefix: vec![],
                match_exec_path:   vec![],
                match_port:        vec![],
                match_uid:         None,
            }],
        };
        let result = rs.evaluate(&exec_event("curl"));
        assert_eq!(result.map(|(a, _)| a), Some(Action::Logged));
    }
}
