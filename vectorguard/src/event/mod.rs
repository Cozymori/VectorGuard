use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub id:         u64,
    pub timestamp:  u64,
    pub source:     EventSource,
    pub process:    ProcessInfo,
    pub parent:     Option<ProcessInfo>,
    pub event_type: EventType,
    pub severity:   Severity,
    pub action:     Action,
    pub rule_name:  Option<String>,
    pub k8s:        Option<K8sMeta>,
    pub raw:        serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid:    u32,
    pub ppid:   u32,
    pub binary: String,
    pub args:   Vec<String>,
    pub uid:    u32,
    pub gid:    u32,
    pub cwd:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventType {
    Exec,
    FileAccess  { path: String, flags: FileFlags },
    Network     { direction: Direction, remote_ip: IpAddr, port: u16, proto: Proto },
    Privilege   { syscall: String, capability: Option<String> },
    Signal      { signum: u32, target_pid: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFlags {
    pub read:    bool,
    pub write:   bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Direction { Inbound, Outbound }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proto { Tcp, Udp, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action { Allowed, Blocked, Killed, Alerted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sMeta {
    pub pod_name:   String,
    pub namespace:  String,
    pub node_name:  String,
    pub container:  ContainerInfo,
    pub labels:     std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id:    String,
    pub name:  String,
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventSource { Tetragon, Falco, Auditd, NativeEbpf }
