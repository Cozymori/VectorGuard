//! Tetragon gRPC streaming adapter.
//! Connects to Tetragon's FineGuidanceSensors.GetEvents RPC and converts
//! events into VectorGuard NormalizedEvents.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::config::TetragonConfig;
use crate::event::{
    self, Action, ContainerInfo, Direction, EventSource, FileFlags, K8sMeta,
    NormalizedEvent, ProcessInfo, Proto, Severity,
};

use super::Adapter;

// Generated gRPC types from proto/tetragon.proto
pub mod pb {
    tonic::include_proto!("tetragon");
}

use pb::{
    fine_guidance_sensors_client::FineGuidanceSensorsClient,
    EventType as TetraEventType, GetEventsRequest,
};

static EVENT_ID: AtomicU64 = AtomicU64::new(0);

pub struct TetragonAdapter {
    endpoint: String,
    buffer:   Vec<NormalizedEvent>,
}

impl TetragonAdapter {
    pub fn new(cfg: &TetragonConfig) -> Self {
        Self { endpoint: cfg.endpoint.clone(), buffer: Vec::new() }
    }

    async fn connect_and_stream(&mut self) -> Result<()> {
        info!("Connecting to Tetragon gRPC: {}", self.endpoint);

        let mut client = FineGuidanceSensorsClient::connect(self.endpoint.clone())
            .await
            .with_context(|| format!("Failed to connect to Tetragon at {}", self.endpoint))?;

        let request = GetEventsRequest {
            allow_list: vec![
                TetraEventType::ProcessExec as i32,
                TetraEventType::ProcessExit as i32,
                TetraEventType::ProcessKprobe as i32,
            ],
            deny_list: vec![],
        };

        let mut stream = client
            .get_events(request)
            .await
            .context("Failed to call GetEvents")?
            .into_inner();

        info!("Tetragon event stream established");

        while let Some(response) = stream.next().await {
            match response {
                Ok(resp) => {
                    if let Some(ev) = convert_response(resp) {
                        self.buffer.push(ev);
                    }
                }
                Err(e) => {
                    warn!("Tetragon stream error: {}", e);
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Adapter for TetragonAdapter {
    async fn next_event(&mut self) -> Result<NormalizedEvent> {
        loop {
            if let Some(ev) = self.buffer.pop() {
                return Ok(ev);
            }
            if let Err(e) = self.connect_and_stream().await {
                warn!("Tetragon connection lost, retrying in 5s: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }

    fn source(&self) -> EventSource {
        EventSource::Tetragon
    }
}

// ── Conversion ───────────────────────────────────────────────

fn convert_response(resp: pb::GetEventsResponse) -> Option<NormalizedEvent> {
    use pb::get_events_response::Event;
    match resp.event? {
        Event::ProcessExec(e)       => convert_exec(e),
        Event::ProcessExit(e)       => convert_exit(e),
        Event::ProcessKprobe(e)     => convert_kprobe(e),
        Event::ProcessTracepoint(e) => convert_tracepoint(e),
        Event::ProcessLoader(_)     => None,
        Event::ProcessUprobe(_)     => None,
    }
}

fn convert_exec(e: pb::ProcessExec) -> Option<NormalizedEvent> {
    let proc = e.process?;
    Some(NormalizedEvent {
        id:         next_id(),
        timestamp:  0,
        source:     EventSource::Tetragon,
        process:    process_info(&proc),
        parent:     e.parent.as_ref().map(process_info),
        event_type: event::EventType::Exec,
        severity:   Severity::Info,
        action:     Action::Allowed,
        rule_name:  None,
        k8s:        k8s_from(&proc),
        raw:        serde_json::Value::Null,
    })
}

fn convert_exit(e: pb::ProcessExit) -> Option<NormalizedEvent> {
    let proc = e.process?;
    let target_pid = proc.pid.unwrap_or(0);
    Some(NormalizedEvent {
        id:         next_id(),
        timestamp:  0,
        source:     EventSource::Tetragon,
        process:    process_info(&proc),
        parent:     e.parent.as_ref().map(process_info),
        event_type: event::EventType::Signal { signum: 0, target_pid },
        severity:   Severity::Info,
        action:     Action::Allowed,
        rule_name:  None,
        k8s:        k8s_from(&proc),
        raw:        serde_json::Value::Null,
    })
}

fn convert_kprobe(e: pb::ProcessKprobe) -> Option<NormalizedEvent> {
    let proc = e.process?;
    let event_type = kprobe_event_type(&e.function_name, &e.args);
    let severity = match &event_type {
        event::EventType::FileAccess { path, .. } if is_sensitive(path) => Severity::High,
        event::EventType::Network { port, .. } if is_suspicious_port(*port) => Severity::Medium,
        _ => Severity::Info,
    };
    Some(NormalizedEvent {
        id:         next_id(),
        timestamp:  0,
        source:     EventSource::Tetragon,
        process:    process_info(&proc),
        parent:     e.parent.as_ref().map(process_info),
        event_type,
        severity,
        action:     Action::Allowed,
        rule_name:  None,
        k8s:        k8s_from(&proc),
        raw:        serde_json::Value::Null,
    })
}

fn convert_tracepoint(e: pb::ProcessTracepoint) -> Option<NormalizedEvent> {
    let proc = e.process?;
    Some(NormalizedEvent {
        id:         next_id(),
        timestamp:  0,
        source:     EventSource::Tetragon,
        process:    process_info(&proc),
        parent:     e.parent.as_ref().map(process_info),
        event_type: event::EventType::Privilege {
            syscall:    format!("{}/{}", e.subsys, e.event),
            capability: None,
        },
        severity:   Severity::Medium,
        action:     Action::Allowed,
        rule_name:  None,
        k8s:        k8s_from(&proc),
        raw:        serde_json::Value::Null,
    })
}

// ── Kprobe → EventType ────────────────────────────────────────

fn kprobe_event_type(func: &str, args: &[pb::KprobeArgument]) -> event::EventType {
    use pb::kprobe_argument::Arg;

    if func.contains("open") || func.contains("vfs_read") || func.contains("vfs_write") {
        let (path, flags) = args.iter().find_map(|a| {
            if let Some(Arg::FileArg(f)) = &a.arg { Some((f.path.clone(), f.flags)) } else { None }
        }).unwrap_or_default();

        return event::EventType::FileAccess {
            path,
            flags: FileFlags {
                read:    flags & 0x1 == 0,
                write:   flags & 0x1 != 0 || flags & 0x2 != 0,
                execute: false,
            },
        };
    }

    if func.contains("connect") || func.contains("tcp") || func.contains("sock") {
        let (remote_ip, port) = args.iter().find_map(|a| {
            if let Some(Arg::SockArg(s)) = &a.arg {
                let ip: IpAddr = s.daddr.parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                Some((ip, s.dport as u16))
            } else { None }
        }).unwrap_or((IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));

        return event::EventType::Network {
            direction: Direction::Outbound,
            remote_ip,
            port,
            proto: Proto::Tcp,
        };
    }

    if func.contains("cap_") || func.contains("setuid") || func.contains("ptrace") {
        return event::EventType::Privilege {
            syscall:    func.to_string(),
            capability: None,
        };
    }

    event::EventType::Exec
}

// ── Helpers ───────────────────────────────────────────────────

fn process_info(p: &pb::Process) -> ProcessInfo {
    ProcessInfo {
        pid:    p.pid.unwrap_or(0),
        ppid:   0,
        uid:    p.uid.unwrap_or(65534),
        gid:    0,
        binary: p.binary.clone(),
        args:   p.arguments.split_whitespace().map(String::from).collect(),
        cwd:    p.cwd.clone(),
    }
}

fn k8s_from(p: &pb::Process) -> Option<K8sMeta> {
    let pod = p.pod.as_ref()?;
    if pod.name.is_empty() { return None; }
    Some(K8sMeta {
        pod_name:  pod.name.clone(),
        namespace: pod.namespace.clone(),
        node_name: String::new(),
        container: ContainerInfo { id: String::new(), name: String::new(), image: String::new() },
        labels:    std::collections::HashMap::new(),
    })
}

fn is_sensitive(path: &str) -> bool {
    const S: &[&str] = &["/etc/shadow", "/etc/sudoers", "/etc/gshadow", "/root/", "/proc/keys"];
    S.iter().any(|p| path.starts_with(p))
}

fn is_suspicious_port(port: u16) -> bool {
    matches!(port, 4444 | 1337 | 31337 | 9001 | 8888 | 6666)
}

fn next_id() -> u64 {
    EVENT_ID.fetch_add(1, Ordering::Relaxed)
}
