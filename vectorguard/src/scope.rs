use crate::config::ScopeConfig;
use crate::event::NormalizedEvent;

/// Filters events by process name against the configured target list.
/// If `targets` is empty, all events pass through.
pub struct ScopeFilter {
    patterns: Vec<glob::Pattern>,
}

impl ScopeFilter {
    pub fn new(cfg: &ScopeConfig) -> Self {
        let patterns = cfg
            .targets
            .iter()
            .filter_map(|t| {
                glob::Pattern::new(t)
                    .map_err(|e| tracing::warn!("Invalid scope pattern '{}': {}", t, e))
                    .ok()
            })
            .collect();

        Self { patterns }
    }

    /// Returns true if the event should be processed (passes the scope filter).
    pub fn allows(&self, event: &NormalizedEvent) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        let binary = &event.process.binary;
        self.patterns.iter().any(|p| p.matches(binary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScopeConfig;
    use crate::event::*;

    fn make_event(binary: &str) -> NormalizedEvent {
        NormalizedEvent {
            id: 0,
            timestamp: 0,
            source: EventSource::NativeEbpf,
            process: ProcessInfo {
                pid: 1, ppid: 0, uid: 0, gid: 0,
                binary: binary.to_string(),
                args: vec![],
                cwd: String::new(),
            },
            parent:     None,
            event_type: EventType::Exec,
            severity:   Severity::Info,
            action:     Action::Allowed,
            k8s:        None,
            raw:        serde_json::Value::Null,
        }
    }

    #[test]
    fn empty_targets_allows_all() {
        let filter = ScopeFilter::new(&ScopeConfig {
            targets: vec![],
            exclude_namespaces: vec![],
        });
        assert!(filter.allows(&make_event("anything")));
    }

    #[test]
    fn exact_match() {
        let filter = ScopeFilter::new(&ScopeConfig {
            targets: vec!["nginx".into()],
            exclude_namespaces: vec![],
        });
        assert!(filter.allows(&make_event("nginx")));
        assert!(!filter.allows(&make_event("sshd")));
    }

    #[test]
    fn glob_match() {
        let filter = ScopeFilter::new(&ScopeConfig {
            targets: vec!["py*".into(), "nginx".into()],
            exclude_namespaces: vec![],
        });
        assert!(filter.allows(&make_event("python3")));
        assert!(filter.allows(&make_event("nginx")));
        assert!(!filter.allows(&make_event("bash")));
    }
}
