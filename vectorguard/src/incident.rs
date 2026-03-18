use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
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

pub struct IncidentLogger {
    path: PathBuf,
}

impl IncidentLogger {
    pub fn new(path: Option<&str>) -> Self {
        let path = PathBuf::from(path.unwrap_or(DEFAULT_INCIDENT_PATH));

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                warn!("Could not create incident log directory {:?}: {}", parent, e);
            }
        }

        info!("Incident logger initialized: {}", path.display());
        Self { path }
    }

    /// Record an incident if the event is Blocked or Alerted.
    /// Returns true if an incident was recorded.
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

        match serde_json::to_string(&record) {
            Ok(json) => {
                match OpenOptions::new().create(true).append(true).open(&self.path) {
                    Ok(mut file) => {
                        if let Err(e) = writeln!(file, "{}", json) {
                            warn!("Failed to write incident: {}", e);
                            return false;
                        }
                        true
                    }
                    Err(e) => {
                        warn!("Failed to open incident file {}: {}", self.path.display(), e);
                        false
                    }
                }
            }
            Err(e) => {
                warn!("Failed to serialize incident: {}", e);
                false
            }
        }
    }
}
