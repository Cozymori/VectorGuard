//! Integration test: scope filter → fast_path → incident logger
//! exercised together with synthetic events. No eBPF, no Qdrant.

use std::time::Duration;

use vectorguard::config::{
    DefaultAction, FastPathConfig, ScopeConfig,
};
use vectorguard::event::{
    Action, Direction, EventSource, EventType, FileFlags, NormalizedEvent,
    ProcessInfo, Proto, Severity,
};
use vectorguard::fast_path::FastPath;
use vectorguard::incident::IncidentLogger;
use vectorguard::scope::ScopeFilter;

fn fast_path_cfg(rules_dir: &str) -> FastPathConfig {
    FastPathConfig {
        enabled:        true,
        rules_path:     rules_dir.to_string(),
        default_action: DefaultAction::Log,
    }
}

fn empty_scope() -> ScopeConfig {
    ScopeConfig {
        targets:             vec![],
        exclude_processes:   vec![],
        include_namespaces:  vec![],
        exclude_namespaces:  vec![],
        label_selectors:     vec![],
    }
}

fn exec_event(binary: &str, uid: u32) -> NormalizedEvent {
    NormalizedEvent {
        id: 1,
        timestamp: 1000,
        source: EventSource::NativeEbpf,
        process: ProcessInfo {
            pid: 100, ppid: 1, uid, gid: uid,
            binary: binary.into(),
            args: vec![], cwd: String::new(),
        },
        parent: None,
        event_type: EventType::Exec,
        severity: Severity::Info,
        action: Action::Allowed,
        rule_name: None,
        k8s: None,
        raw: serde_json::Value::Null,
    }
}

fn file_event(binary: &str, path: &str) -> NormalizedEvent {
    let mut ev = exec_event(binary, 1000);
    ev.event_type = EventType::FileAccess {
        path: path.into(),
        flags: FileFlags { read: true, write: false, execute: false },
    };
    ev
}

fn net_event(binary: &str, port: u16) -> NormalizedEvent {
    let mut ev = exec_event(binary, 1000);
    ev.event_type = EventType::Network {
        direction: Direction::Outbound,
        remote_ip: "10.0.0.1".parse().unwrap(),
        port,
        proto: Proto::Tcp,
    };
    ev
}

/// Write a single rule file in a fresh tempdir; returns the dir path.
fn write_rules(name: &str, toml: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vg-test-rules-{}-{}",
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("rule.toml"), toml).unwrap();
    dir
}

/// Read incident log lines (newline-separated JSON).
fn read_incident_lines(path: &std::path::Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(s)  => s.lines().map(String::from).collect(),
        Err(_) => Vec::new(),
    }
}

fn temp_incident_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "vg-pipeline-{}-{}.jsonl",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ))
}

// ── Pipeline tests ──────────────────────────────────────────────

#[tokio::test]
async fn block_rule_results_in_incident() {
    let rules_dir = write_rules(
        "block-shadow",
        r#"
            [[rules]]
            name = "block-shadow-access"
            action = "block"
            match_path_prefix = ["/etc/shadow"]
        "#,
    );
    let incident_path = temp_incident_path("block-shadow");

    let scope = ScopeFilter::new(&empty_scope());
    let fp    = FastPath::new(&fast_path_cfg(rules_dir.to_str().unwrap()));
    let log   = IncidentLogger::new(Some(incident_path.to_str().unwrap()));

    let mut ev = file_event("cat", "/etc/shadow");
    assert!(scope.allows(&ev));
    fp.evaluate(&mut ev);
    log.record(&ev);

    tokio::time::sleep(Duration::from_millis(150)).await;

    let lines = read_incident_lines(&incident_path);
    assert_eq!(lines.len(), 1, "expected exactly one incident line");
    assert!(lines[0].contains("\"action\":\"Blocked\""));
    assert!(lines[0].contains("\"rule\":\"block-shadow-access\""));
    assert!(lines[0].contains("\"event_type\":\"FileAccess:/etc/shadow\""));

    let _ = std::fs::remove_file(&incident_path);
    let _ = std::fs::remove_dir_all(&rules_dir);
}

#[tokio::test]
async fn allowed_events_produce_no_incident() {
    let rules_dir = write_rules("allow-all", "");
    let incident_path = temp_incident_path("allow-all");

    let scope = ScopeFilter::new(&empty_scope());
    let fp    = FastPath::new(&fast_path_cfg(rules_dir.to_str().unwrap()));
    let log   = IncidentLogger::new(Some(incident_path.to_str().unwrap()));

    let mut ev = exec_event("ls", 1000);
    assert!(scope.allows(&ev));
    fp.evaluate(&mut ev);
    // With default_action=log + empty/builtin rules, ls/Exec won't match a
    // block or alert rule; action stays Logged/Allowed.
    assert!(!matches!(ev.action, Action::Blocked | Action::Alerted));
    log.record(&ev);

    tokio::time::sleep(Duration::from_millis(150)).await;

    let lines = read_incident_lines(&incident_path);
    assert!(lines.is_empty(), "Allowed/Logged events must not log incidents");

    let _ = std::fs::remove_file(&incident_path);
    let _ = std::fs::remove_dir_all(&rules_dir);
}

#[tokio::test]
async fn scope_exclude_skips_event_before_rules() {
    let rules_dir = write_rules(
        "block-cat",
        r#"
            [[rules]]
            name = "block-cat"
            action = "block"
            match_process = ["cat"]
        "#,
    );
    let incident_path = temp_incident_path("scope-exclude");

    let mut cfg = empty_scope();
    cfg.exclude_processes = vec!["cat".into()];
    let scope = ScopeFilter::new(&cfg);
    let fp    = FastPath::new(&fast_path_cfg(rules_dir.to_str().unwrap()));
    let log   = IncidentLogger::new(Some(incident_path.to_str().unwrap()));

    let mut ev = exec_event("cat", 1000);
    // The scope filter drops the event before the rule engine sees it.
    assert!(!scope.allows(&ev));
    // The rest of the pipeline simply doesn't run for excluded events.
    // Verify that no incident is recorded if the pipeline is short-circuited.
    if scope.allows(&ev) {
        fp.evaluate(&mut ev);
        log.record(&ev);
    }

    tokio::time::sleep(Duration::from_millis(150)).await;
    let lines = read_incident_lines(&incident_path);
    assert!(lines.is_empty(), "excluded events must not reach the logger");

    let _ = std::fs::remove_file(&incident_path);
    let _ = std::fs::remove_dir_all(&rules_dir);
}

#[tokio::test]
async fn alert_rule_escalates_severity_and_records_incident() {
    let rules_dir = write_rules(
        "alert-port",
        r#"
            [[rules]]
            name = "alert-rev-shell"
            action = "alert"
            match_port = [4444]
        "#,
    );
    let incident_path = temp_incident_path("alert-port");

    let scope = ScopeFilter::new(&empty_scope());
    let fp    = FastPath::new(&fast_path_cfg(rules_dir.to_str().unwrap()));
    let log   = IncidentLogger::new(Some(incident_path.to_str().unwrap()));

    let mut ev = net_event("nc", 4444);
    assert_eq!(ev.severity, Severity::Info);
    fp.evaluate(&mut ev);
    assert_eq!(ev.severity, Severity::High, "alert should escalate severity");
    log.record(&ev);

    tokio::time::sleep(Duration::from_millis(150)).await;

    let lines = read_incident_lines(&incident_path);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"action\":\"Alerted\""));
    assert!(lines[0].contains("\"rule\":\"alert-rev-shell\""));

    let _ = std::fs::remove_file(&incident_path);
    let _ = std::fs::remove_dir_all(&rules_dir);
}
