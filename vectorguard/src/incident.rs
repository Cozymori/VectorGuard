use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::event::{Action, NormalizedEvent};

const DEFAULT_INCIDENT_PATH: &str = "/var/log/vectorguard/incidents.jsonl";

#[derive(Debug, Serialize)]
struct IncidentRecord {
    timestamp:  u64,
    pid:        u32,
    ppid:       u32,
    uid:        u32,
    binary:     String,
    event_type: String,
    rule:       Option<String>,
    action:     String,
}

/// Append-only incident log. Writes are sent through a bounded channel to a
/// dedicated writer task so callers never block on disk I/O.
pub struct IncidentLogger {
    tx: Mutex<Option<mpsc::Sender<String>>>,
}

impl IncidentLogger {
    pub fn new(path: Option<&str>) -> Self {
        let path = PathBuf::from(path.unwrap_or(DEFAULT_INCIDENT_PATH));

        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                warn!("Could not create incident log directory {:?}: {}", parent, e);
            }
        }

        let (tx, rx) = mpsc::channel::<String>(1024);
        tokio::spawn(writer_task(path.clone(), rx));

        info!("Incident logger initialized: {}", path.display());
        Self { tx: Mutex::new(Some(tx)) }
    }

    /// Queue an incident if the event is Blocked / Alerted / Killed.
    /// Returns true if the event was queued (or didn't need to be), false on
    /// serialization failure or queue overflow.
    pub fn record(&self, event: &NormalizedEvent) -> bool {
        if !matches!(event.action, Action::Blocked | Action::Alerted | Action::Killed) {
            return false;
        }

        let event_type = match &event.event_type {
            crate::event::EventType::Exec                       => "Exec".to_string(),
            crate::event::EventType::FileAccess { path, .. }    => format!("FileAccess:{}", path),
            crate::event::EventType::Network { port, proto, .. } => format!("Network:{:?}:{}", proto, port),
            crate::event::EventType::Privilege { syscall, .. }  => format!("Privilege:{}", syscall),
            crate::event::EventType::Signal { signum, .. }      => format!("Signal:{}", signum),
        };

        let record = IncidentRecord {
            timestamp:  event.timestamp,
            pid:        event.process.pid,
            ppid:       event.process.ppid,
            uid:        event.process.uid,
            binary:     event.process.binary.clone(),
            event_type,
            rule:       event.rule_name.clone(),
            action:     format!("{:?}", event.action),
        };

        let json = match serde_json::to_string(&record) {
            Ok(j)  => j,
            Err(e) => { warn!("Failed to serialize incident: {}", e); return false; }
        };

        // Non-blocking send. If the writer is backlogged, drop rather than
        // stall the pipeline — losing audit lines is better than dropping
        // live events.
        if let Ok(guard) = self.tx.try_lock() {
            if let Some(tx) = guard.as_ref() {
                if tx.try_send(json).is_err() {
                    warn!("Incident writer backlogged; dropping line");
                    return false;
                }
            }
        }
        true
    }
}

async fn writer_task(path: PathBuf, mut rx: mpsc::Receiver<String>) {
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        Ok(f)  => f,
        Err(e) => {
            warn!("Failed to open incident file {}: {}", path.display(), e);
            return;
        }
    };

    while let Some(line) = rx.recv().await {
        if let Err(e) = file.write_all(line.as_bytes()).await {
            warn!("Incident write failed: {}", e);
            continue;
        }
        let _ = file.write_all(b"\n").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use std::time::Duration;

    fn make_event(action: Action, binary: &str, rule: Option<&str>) -> NormalizedEvent {
        NormalizedEvent {
            id: 1,
            timestamp: 1234,
            source: EventSource::NativeEbpf,
            process: ProcessInfo {
                pid: 42, ppid: 1, uid: 1000, gid: 1000,
                binary: binary.to_string(),
                args: vec![], cwd: String::new(),
            },
            parent: None,
            event_type: EventType::Exec,
            severity: Severity::High,
            action,
            rule_name: rule.map(String::from),
            k8s: None,
            raw: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn skips_allowed_events() {
        let tmp = tempfile_path("vg-incident-allowed");
        let logger = IncidentLogger::new(Some(tmp.to_str().unwrap()));
        let ev = make_event(Action::Allowed, "ls", None);
        assert_eq!(logger.record(&ev), false);
    }

    #[tokio::test]
    async fn skips_logged_events() {
        let tmp = tempfile_path("vg-incident-logged");
        let logger = IncidentLogger::new(Some(tmp.to_str().unwrap()));
        let ev = make_event(Action::Logged, "curl", Some("log-curl"));
        assert_eq!(logger.record(&ev), false);
    }

    #[tokio::test]
    async fn writes_blocked_event_to_file() {
        let tmp = tempfile_path("vg-incident-blocked");
        {
            let logger = IncidentLogger::new(Some(tmp.to_str().unwrap()));
            let ev = make_event(Action::Blocked, "nc", Some("block-nc"));
            assert!(logger.record(&ev));
            // Allow the async writer task to flush.
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert!(contents.contains("\"action\":\"Blocked\""), "{}", contents);
        assert!(contents.contains("\"rule\":\"block-nc\""), "{}", contents);
        assert!(contents.contains("\"binary\":\"nc\""), "{}", contents);
        assert!(contents.contains("\"pid\":42"), "{}", contents);
        assert!(contents.ends_with('\n'));
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn includes_event_type_detail() {
        let tmp = tempfile_path("vg-incident-detail");
        {
            let logger = IncidentLogger::new(Some(tmp.to_str().unwrap()));
            let mut ev = make_event(Action::Alerted, "cat", Some("alert-shadow"));
            ev.event_type = EventType::FileAccess {
                path: "/etc/shadow".into(),
                flags: FileFlags { read: true, write: false, execute: false },
            };
            assert!(logger.record(&ev));
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert!(
            contents.contains("\"event_type\":\"FileAccess:/etc/shadow\""),
            "{}", contents
        );
        let _ = std::fs::remove_file(&tmp);
    }

    fn tempfile_path(label: &str) -> std::path::PathBuf {
        let name = format!(
            "{}-{}.jsonl",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        std::env::temp_dir().join(name)
    }
}
