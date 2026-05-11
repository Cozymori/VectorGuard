//! Integration test: drive the async incident logger from multiple
//! concurrent tasks and verify every record lands on disk in valid JSON.

use std::time::Duration;
use tokio::task::JoinSet;

use vectorguard::event::{
    Action, EventSource, EventType, NormalizedEvent, ProcessInfo, Severity,
};
use vectorguard::incident::IncidentLogger;

fn tempfile(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "vg-incident-it-{}-{}.jsonl",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ))
}

fn blocked_event(pid: u32, binary: &str, rule: &str) -> NormalizedEvent {
    NormalizedEvent {
        id: pid as u64,
        timestamp: 1000 + pid as u64,
        source: EventSource::NativeEbpf,
        process: ProcessInfo {
            pid, ppid: 1, uid: 1000, gid: 1000,
            binary: binary.into(),
            args: vec![],
            cwd: String::new(),
        },
        parent: None,
        event_type: EventType::Exec,
        severity: Severity::High,
        action: Action::Blocked,
        rule_name: Some(rule.into()),
        k8s: None,
        raw: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn writes_many_records_in_parallel() {
    let path = tempfile("parallel");
    let logger = std::sync::Arc::new(IncidentLogger::new(Some(path.to_str().unwrap())));

    let mut joinset = JoinSet::new();
    for i in 0..50u32 {
        let log = std::sync::Arc::clone(&logger);
        joinset.spawn(async move {
            let ev = blocked_event(i, &format!("proc-{}", i), "test-rule");
            log.record(&ev)
        });
    }

    let mut accepted = 0;
    while let Some(res) = joinset.join_next().await {
        if res.unwrap() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 50, "every record() call should accept");

    // Drain the writer task — give it ample time to flush.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 50, "expected 50 lines on disk, got {}", lines.len());

    // Every line must parse as JSON with the expected shape.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|_| panic!("invalid JSON line: {}", line));
        assert!(v.get("pid").and_then(|x| x.as_u64()).is_some());
        assert_eq!(v["action"], "Blocked");
        assert_eq!(v["rule"], "test-rule");
        assert!(v["binary"].as_str().unwrap().starts_with("proc-"));
    }

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn appends_across_multiple_record_calls() {
    let path = tempfile("sequence");
    let logger = IncidentLogger::new(Some(path.to_str().unwrap()));

    for i in 0..5u32 {
        let ev = blocked_event(i, "sequential", "test-seq");
        assert!(logger.record(&ev));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let contents = std::fs::read_to_string(&path).unwrap();
    let pids: Vec<u64> = contents
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["pid"].as_u64().unwrap())
        .collect();

    assert_eq!(pids, vec![0, 1, 2, 3, 4], "writes must preserve submit order");

    let _ = std::fs::remove_file(&path);
}
