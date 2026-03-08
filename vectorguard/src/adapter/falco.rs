use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::sleep;
use tracing::debug;

use crate::config::FalcoConfig;
use crate::event::*;

use super::Adapter;

static EVENT_ID: AtomicU64 = AtomicU64::new(0);

/// Falco JSON log file tail adapter
/// Falco config: `json_output: true`, `json_include_output_property: true`
pub struct FalcoAdapter {
    log_path: String,
    reader:   Option<BufReader<tokio::fs::File>>,
}

impl FalcoAdapter {
    pub fn new(cfg: &FalcoConfig) -> Self {
        Self {
            log_path: cfg.log_path.clone(),
            reader:   None,
        }
    }

    async fn ensure_reader(&mut self) -> Result<&mut BufReader<tokio::fs::File>> {
        if self.reader.is_none() {
            let file = tokio::fs::File::open(&self.log_path).await?;
            // Seek to end of file → receive only new events
            use tokio::io::AsyncSeekExt;
            let mut file = file;
            file.seek(std::io::SeekFrom::End(0)).await?;
            self.reader = Some(BufReader::new(file));
        }
        Ok(self.reader.as_mut().unwrap())
    }
}

#[async_trait]
impl Adapter for FalcoAdapter {
    async fn next_event(&mut self) -> Result<NormalizedEvent> {
        loop {
            let reader = match self.ensure_reader().await {
                Ok(r)  => r,
                Err(e) => {
                    sleep(Duration::from_secs(1)).await;
                    return Err(anyhow::anyhow!("Failed to open Falco log file: {}", e));
                }
            };

            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;

            if n == 0 {
                // EOF → wait for new data
                sleep(Duration::from_millis(200)).await;
                continue;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match parse_falco_json(line) {
                Ok(ev)  => return Ok(ev),
                Err(e)  => {
                    debug!("Skipping Falco event parse error: {}", e);
                    continue;
                }
            }
        }
    }

    fn source(&self) -> EventSource {
        EventSource::Falco
    }
}

/// Parse a Falco JSON event
/// Example: {"time":"...","rule":"...","priority":"Warning","output_fields":{...}}
fn parse_falco_json(line: &str) -> Result<NormalizedEvent> {
    let v: serde_json::Value = serde_json::from_str(line)?;
    let fields = &v["output_fields"];

    let priority = v["priority"].as_str().unwrap_or("Informational");
    let severity  = falco_priority_to_severity(priority);

    let binary = fields["proc.name"].as_str().unwrap_or("").to_string();
    let pid    = fields["proc.pid"].as_u64().unwrap_or(0) as u32;
    let ppid   = fields["proc.ppid"].as_u64().unwrap_or(0) as u32;
    let uid    = fields["user.uid"].as_u64().unwrap_or(65534) as u32;

    // Determine event type
    let evt_type = fields["evt.type"].as_str().unwrap_or("");
    let event_type = match evt_type {
        "execve" | "execveat" => EventType::Exec,
        "openat" | "open" => {
            let path  = fields["fd.name"].as_str().unwrap_or("").to_string();
            let flags = fields["fd.openflags"].as_u64().unwrap_or(0) as u32;
            EventType::FileAccess {
                path,
                flags: FileFlags {
                    read:    flags & 0x1 == 0,
                    write:   flags & 0x1 != 0 || flags & 0x2 != 0,
                    execute: false,
                },
            }
        }
        "connect" => {
            let port = fields["fd.sport"].as_u64().unwrap_or(0) as u16;
            EventType::Network {
                direction: Direction::Outbound,
                remote_ip: "0.0.0.0".parse().unwrap(),
                port,
                proto: Proto::Tcp,
            }
        }
        _ => EventType::Exec, // unknown → classify as Exec
    };

    Ok(NormalizedEvent {
        id:         EVENT_ID.fetch_add(1, Ordering::Relaxed),
        timestamp:  0,
        source:     EventSource::Falco,
        process:    ProcessInfo {
            pid, ppid, uid, gid: 0,
            binary,
            args: vec![],
            cwd:  String::new(),
        },
        parent:     None,
        event_type,
        severity,
        action:     Action::Allowed,
        k8s:        None,
        raw:        v,
    })
}

fn falco_priority_to_severity(p: &str) -> Severity {
    match p {
        "Emergency" | "Alert" | "Critical" => Severity::Critical,
        "Error"                            => Severity::High,
        "Warning"                          => Severity::Medium,
        "Notice"                           => Severity::Low,
        _                                  => Severity::Info,
    }
}
