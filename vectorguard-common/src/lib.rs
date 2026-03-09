//! Type definitions shared between the eBPF program and userspace
//! Must compile in both no_std (eBPF) and std (userspace) environments

#![cfg_attr(not(feature = "user"), no_std)]


/// Raw event passed from kernel → userspace via eBPF Ring Buffer
/// C-compatible layout (shared memory with eBPF)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawEvent {
    pub kind:      EventKind,
    pub timestamp: u64,   // nanoseconds since boot
    pub pid:       u32,
    pub ppid:      u32,
    pub uid:       u32,
    pub gid:       u32,
    /// Process binary path (null-terminated)
    pub comm:      [u8; 64],
    /// Additional data per event type
    pub payload:   EventPayload,
    /// Set to 1 by eBPF when the kernel already took blocking action (SIGKILL / EPERM)
    pub blocked:   u8,
    pub _pad:      [u8; 7],
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Exec        = 0,
    FileOpen    = 1,
    NetConnect  = 2,
    Privilege   = 3,
}

/// Per-event-type payload (union to save memory)
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
    pub flags: u32,            // O_RDONLY, O_WRONLY, O_RDWR, etc.
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

/// Helper used only in userspace
#[cfg(feature = "user")]
impl RawEvent {
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}
