//! eBPF 프로그램과 userspace 간 공유되는 타입 정의
//! no_std 환경(eBPF)과 std 환경(userspace) 모두 컴파일 가능해야 함

#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// eBPF Ring Buffer를 통해 커널→유저스페이스로 전달되는 raw 이벤트
/// C-compatible 레이아웃 (eBPF와 메모리 공유)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawEvent {
    pub kind:      EventKind,
    pub timestamp: u64,   // nanoseconds since boot
    pub pid:       u32,
    pub ppid:      u32,
    pub uid:       u32,
    pub gid:       u32,
    /// 프로세스 바이너리 경로 (null-terminated)
    pub comm:      [u8; 64],
    /// 이벤트 종류별 추가 데이터
    pub payload:   EventPayload,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Exec        = 0,
    FileOpen    = 1,
    NetConnect  = 2,
    Privilege   = 3,
}

/// 이벤트 종류별 payload (union으로 메모리 절약)
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub exec:       ExecPayload,
    pub file:       FilePayload,
    pub net:        NetPayload,
    pub privilege:  PrivilegePayload,
}

impl core::fmt::Debug for EventPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<payload>")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecPayload {
    pub filename: [u8; 256],
    pub argv:     [u8; 512],   // space-joined args
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FilePayload {
    pub path:  [u8; 256],
    pub flags: u32,            // O_RDONLY, O_WRONLY, O_RDWR 등
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetPayload {
    pub dst_ip:   u32,         // IPv4 big-endian
    pub dst_port: u16,
    pub proto:    u8,          // 6=TCP, 17=UDP
    pub _pad:     u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PrivilegePayload {
    pub syscall_nr: u32,
    pub cap:        u64,       // capability bitmask
}

/// userspace에서만 쓰는 helper
#[cfg(feature = "user")]
impl RawEvent {
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}
