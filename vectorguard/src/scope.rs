//! Scope Filter: decides which events enter the processing pipeline.
//!
//! Filtering layers (applied in order — an event must pass ALL):
//!
//! 1. **Process target** — `targets` glob list matched against binary name.
//!    Empty list = all processes pass.
//!
//! 2. **K8s namespace include** — `include_namespaces` glob list.
//!    If non-empty, a K8s event whose namespace does NOT match any pattern is
//!    dropped. Non-K8s events (no K8sMeta) are unaffected by this rule.
//!
//! 3. **K8s namespace exclude** — `exclude_namespaces` glob list.
//!    A K8s event whose namespace matches ANY pattern is dropped regardless of
//!    other rules. Non-K8s events pass through unconditionally.
//!
//! 4. **K8s label selector** — `label_selectors` list of "key=value" strings.
//!    All pairs must match the event's pod labels. Non-K8s events pass.

use crate::config::ScopeConfig;
use crate::event::NormalizedEvent;

pub struct ScopeFilter {
    target_patterns:    Vec<glob::Pattern>,
    exclude_processes:  Vec<glob::Pattern>,
    include_ns:         Vec<glob::Pattern>,
    exclude_ns:         Vec<glob::Pattern>,
    label_selectors:    Vec<(String, String)>,
}

impl ScopeFilter {
    pub fn new(cfg: &ScopeConfig) -> Self {
        let target_patterns  = compile_patterns(&cfg.targets,             "target");
        let exclude_processes = compile_patterns(&cfg.exclude_processes,  "exclude_processes");
        let include_ns       = compile_patterns(&cfg.include_namespaces,  "include_namespaces");
        let exclude_ns       = compile_patterns(&cfg.exclude_namespaces,  "exclude_namespaces");

        let label_selectors = cfg.label_selectors.iter()
            .filter_map(|s| {
                let mut parts = s.splitn(2, '=');
                let k = parts.next()?.trim().to_string();
                let v = parts.next()?.trim().to_string();
                if k.is_empty() {
                    tracing::warn!("Invalid label selector (no key): '{}'", s);
                    return None;
                }
                Some((k, v))
            })
            .collect();

        Self { target_patterns, exclude_processes, include_ns, exclude_ns, label_selectors }
    }

    /// Returns `true` if the event passes all scope rules and should be processed.
    pub fn allows(&self, event: &NormalizedEvent) -> bool {
        let binary = &event.process.binary;

        // ── 0. Process exclude filter (always applied) ───────────
        if self.exclude_processes.iter().any(|p| p.matches(binary)) {
            return false;
        }

        // ── 1. Process target filter ─────────────────────────────
        if !self.target_patterns.is_empty()
            && !self.target_patterns.iter().any(|p| p.matches(binary))
        {
            return false;
        }

        // ── K8s-specific filters (only when K8sMeta is present) ──
        if let Some(k8s) = &event.k8s {
            let ns = k8s.namespace.as_str();

            // ── 2. Namespace include filter ──────────────────────
            if !self.include_ns.is_empty() && !self.include_ns.iter().any(|p| p.matches(ns)) {
                return false;
            }

            // ── 3. Namespace exclude filter ──────────────────────
            if self.exclude_ns.iter().any(|p| p.matches(ns)) {
                return false;
            }

            // ── 4. Label selector filter ─────────────────────────
            for (key, val) in &self.label_selectors {
                match k8s.labels.get(key) {
                    Some(actual) if actual == val => {}
                    _ => return false,
                }
            }
        }
        // Non-K8s events skip namespace/label checks entirely.

        true
    }
}

fn compile_patterns(raw: &[String], field: &str) -> Vec<glob::Pattern> {
    raw.iter()
        .filter_map(|s| {
            glob::Pattern::new(s)
                .map_err(|e| tracing::warn!("Invalid {} pattern '{}': {}", field, s, e))
                .ok()
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScopeConfig;
    use crate::event::*;
    use std::collections::HashMap;

    fn base_cfg() -> ScopeConfig {
        ScopeConfig {
            targets:             vec![],
            exclude_processes:   vec![],
            include_namespaces:  vec![],
            exclude_namespaces:  vec![],
            label_selectors:     vec![],
        }
    }

    fn make_event(binary: &str, k8s: Option<K8sMeta>) -> NormalizedEvent {
        NormalizedEvent {
            id: 0, timestamp: 0,
            source: EventSource::NativeEbpf,
            process: ProcessInfo {
                pid: 1, ppid: 0, uid: 0, gid: 0,
                binary: binary.to_string(),
                args: vec![], cwd: String::new(),
            },
            parent: None,
            event_type: EventType::Exec,
            severity: Severity::Info,
            action: Action::Allowed,
            rule_name: None,
            k8s,
            raw: serde_json::Value::Null,
        }
    }

    fn k8s(ns: &str, labels: &[(&str, &str)]) -> K8sMeta {
        K8sMeta {
            pod_name:  "test-pod".into(),
            namespace: ns.into(),
            node_name: "node-1".into(),
            container: ContainerInfo {
                id:    "abc".into(),
                name:  "app".into(),
                image: "nginx:latest".into(),
            },
            labels: labels.iter().map(|(k,v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    // ── process target tests ─────────────────────────────────────

    #[test]
    fn empty_targets_allows_all() {
        let f = ScopeFilter::new(&base_cfg());
        assert!(f.allows(&make_event("anything", None)));
    }

    #[test]
    fn target_exact_match() {
        let f = ScopeFilter::new(&ScopeConfig { targets: vec!["nginx".into()], ..base_cfg() });
        assert!( f.allows(&make_event("nginx", None)));
        assert!(!f.allows(&make_event("sshd",  None)));
    }

    #[test]
    fn target_glob_match() {
        let f = ScopeFilter::new(&ScopeConfig {
            targets: vec!["py*".into(), "nginx".into()], ..base_cfg()
        });
        assert!( f.allows(&make_event("python3", None)));
        assert!( f.allows(&make_event("nginx",   None)));
        assert!(!f.allows(&make_event("bash",    None)));
    }

    // ── K8s namespace include tests ──────────────────────────────

    #[test]
    fn include_ns_allows_matching_namespace() {
        let f = ScopeFilter::new(&ScopeConfig {
            include_namespaces: vec!["production".into()], ..base_cfg()
        });
        assert!( f.allows(&make_event("nginx", Some(k8s("production", &[])))));
        assert!(!f.allows(&make_event("nginx", Some(k8s("kube-system", &[])))));
    }

    #[test]
    fn include_ns_does_not_affect_bare_metal_events() {
        let f = ScopeFilter::new(&ScopeConfig {
            include_namespaces: vec!["production".into()], ..base_cfg()
        });
        // No K8sMeta → include_ns is not applied
        assert!(f.allows(&make_event("nginx", None)));
    }

    #[test]
    fn include_ns_glob_pattern() {
        let f = ScopeFilter::new(&ScopeConfig {
            include_namespaces: vec!["prod-*".into()], ..base_cfg()
        });
        assert!( f.allows(&make_event("app", Some(k8s("prod-eu", &[])))));
        assert!( f.allows(&make_event("app", Some(k8s("prod-us", &[])))));
        assert!(!f.allows(&make_event("app", Some(k8s("staging", &[])))));
    }

    // ── K8s namespace exclude tests ──────────────────────────────

    #[test]
    fn exclude_ns_drops_matching_namespace() {
        let f = ScopeFilter::new(&ScopeConfig {
            exclude_namespaces: vec!["kube-system".into(), "kube-public".into()], ..base_cfg()
        });
        assert!(!f.allows(&make_event("coredns", Some(k8s("kube-system", &[])))));
        assert!(!f.allows(&make_event("proxy",   Some(k8s("kube-public", &[])))));
        assert!( f.allows(&make_event("nginx",   Some(k8s("production",  &[])))));
    }

    #[test]
    fn exclude_ns_does_not_affect_bare_metal_events() {
        let f = ScopeFilter::new(&ScopeConfig {
            exclude_namespaces: vec!["kube-system".into()], ..base_cfg()
        });
        assert!(f.allows(&make_event("coredns", None)));
    }

    #[test]
    fn exclude_overrides_include() {
        // Both lists present; exclude takes precedence
        let f = ScopeFilter::new(&ScopeConfig {
            include_namespaces: vec!["prod*".into()],
            exclude_namespaces: vec!["prod-dmz".into()],
            ..base_cfg()
        });
        assert!( f.allows(&make_event("app", Some(k8s("prod-eu",  &[])))));
        assert!(!f.allows(&make_event("app", Some(k8s("prod-dmz", &[])))));
        assert!(!f.allows(&make_event("app", Some(k8s("staging",  &[])))));
    }

    // ── K8s label selector tests ─────────────────────────────────

    #[test]
    fn label_selector_all_must_match() {
        let f = ScopeFilter::new(&ScopeConfig {
            label_selectors: vec!["app=nginx".into(), "env=prod".into()], ..base_cfg()
        });
        assert!( f.allows(&make_event("nginx", Some(k8s("prod", &[("app","nginx"),("env","prod")])))));
        assert!(!f.allows(&make_event("nginx", Some(k8s("prod", &[("app","nginx"),("env","staging")])))));
        assert!(!f.allows(&make_event("nginx", Some(k8s("prod", &[("app","nginx")])))));
    }

    #[test]
    fn label_selector_does_not_affect_bare_metal() {
        let f = ScopeFilter::new(&ScopeConfig {
            label_selectors: vec!["app=nginx".into()], ..base_cfg()
        });
        assert!(f.allows(&make_event("nginx", None)));
    }

    // ── Combined filter tests ────────────────────────────────────

    #[test]
    fn combined_target_and_namespace() {
        let f = ScopeFilter::new(&ScopeConfig {
            targets:            vec!["nginx".into()],
            exclude_processes:  vec![],
            include_namespaces: vec!["production".into()],
            exclude_namespaces: vec!["kube-system".into()],
            label_selectors:    vec![],
        });
        // Right binary, right namespace
        assert!( f.allows(&make_event("nginx", Some(k8s("production", &[])))));
        // Wrong binary
        assert!(!f.allows(&make_event("sshd",  Some(k8s("production", &[])))));
        // Excluded namespace
        assert!(!f.allows(&make_event("nginx", Some(k8s("kube-system",&[])))));
        // Not in include list
        assert!(!f.allows(&make_event("nginx", Some(k8s("staging",    &[])))));
    }
}
