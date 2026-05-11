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
