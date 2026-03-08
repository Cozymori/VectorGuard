use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::sleep;
use tracing::debug;

use crate::config::AuditdConfig;
use crate::event::*;

use super::Adapter;

static EVENT_ID: AtomicU64 = AtomicU64::new(0);

/// auditd text log tail adapter
/// Parses /var/log/audit/audit.log format
pub struct AuditdAdapter {
    log_path: String,
    reader:   Option<BufReader<tokio::fs::File>>,
}

impl AuditdAdapter {
    pub fn new(cfg: &AuditdConfig) -> Self {
        Self {
            log_path: cfg.log_path.clone(),
            reader:   None,
        }
    }

    async fn ensure_reader(&mut self) -> Result<&mut BufReader<tokio::fs::File>> {
        if self.reader.is_none() {
            let file = tokio::fs::File::open(&self.log_path).await?;
            use tokio::io::AsyncSeekExt;
            let mut file = file;
            file.seek(std::io::SeekFrom::End(0)).await?;
            self.reader = Some(BufReader::new(file));
        }
        Ok(self.reader.as_mut().unwrap())
    }
}

#[async_trait]
impl Adapter for AuditdAdapter {
    async fn next_event(&mut self) -> Result<NormalizedEvent> {
        loop {
            let reader = match self.ensure_reader().await {
                Ok(r)  => r,
                Err(e) => {
                    sleep(Duration::from_secs(1)).await;
                    return Err(anyhow::anyhow!("Failed to open auditd log file: {}", e));
                }
            };

            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;

            if n == 0 {
                sleep(Duration::from_millis(200)).await;
                continue;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Only convert SYSCALL records to events
            if !line.contains("type=SYSCALL") {
                continue;
            }

            match parse_auditd_syscall(line) {
                Ok(ev)  => return Ok(ev),
                Err(e)  => {
                    debug!("Skipping auditd parse error: {}", e);
                    continue;
                }
            }
        }
    }

    fn source(&self) -> EventSource {
        EventSource::Auditd
    }
}

/// Parse an auditd SYSCALL record
/// Format: type=SYSCALL msg=audit(...): arch=... syscall=N ... pid=N ppid=N uid=N ... comm="..." exe="..."
fn parse_auditd_syscall(line: &str) -> Result<NormalizedEvent> {
    let fields = parse_kv(line);

    let syscall_nr: u32 = fields.get("syscall").and_then(|s| s.parse().ok()).unwrap_or(0);
    let pid:  u32 = fields.get("pid").and_then(|s| s.parse().ok()).unwrap_or(0);
    let ppid: u32 = fields.get("ppid").and_then(|s| s.parse().ok()).unwrap_or(0);
    let uid:  u32 = fields.get("uid").and_then(|s| s.parse().ok()).unwrap_or(65534);

    let comm = fields.get("comm").map(|s| unquote(s)).unwrap_or_default();
    let exe  = fields.get("exe").map(|s| unquote(s)).unwrap_or_default();

    // Determine event type from syscall number (x86_64)
    let event_type = match syscall_nr {
        59 | 322 => EventType::Exec, // execve, execveat
        2 | 257  => EventType::FileAccess { // open, openat
            path:  exe.clone(),
            flags: FileFlags { read: true, write: false, execute: false },
        },
        42 | 288 => EventType::Network { // connect, accept4
            direction: Direction::Outbound,
            remote_ip: "0.0.0.0".parse().unwrap(),
            port: 0,
            proto: Proto::Tcp,
        },
        _ => EventType::Privilege {
            syscall:    syscall_nr.to_string(),
            capability: None,
        },
    };

    let severity = if uid == 0 { Severity::Medium } else { Severity::Info };

    Ok(NormalizedEvent {
        id:         EVENT_ID.fetch_add(1, Ordering::Relaxed),
        timestamp:  0,
        source:     EventSource::Auditd,
        process:    ProcessInfo {
            pid, ppid, uid, gid: 0,
            binary: if comm.is_empty() { exe } else { comm },
            args:   vec![],
            cwd:    String::new(),
        },
        parent:     None,
        event_type,
        severity,
        action:     Action::Allowed,
        k8s:        None,
        raw:        serde_json::Value::String(line.to_string()),
    })
}

/// Parse key=value pairs from an auditd log line
fn parse_kv(line: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for token in line.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}
