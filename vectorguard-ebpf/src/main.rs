#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
};
use vectorguard_common::{EventKind, ExecPayload, RawEvent};

// ── Ring Buffer: eBPF to userspace ────────────────────────────
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1MB

// ── execve 트레이스포인트 ──────────────────────────────────────
#[tracepoint]
pub fn handle_exec(ctx: TracePointContext) -> u32 {
    match try_handle_exec(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 1,
    }
}

fn try_handle_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = (pid_tgid >> 32) as u32;
    let ppid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut entry = match EVENTS.reserve::<RawEvent>(0) {
        Some(e) => e,
        None    => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).kind      = EventKind::Exec;
        (*event).timestamp = bpf_ktime_get_ns();
        (*event).pid       = pid;
        (*event).ppid      = ppid;
        (*event).uid       = uid;
        (*event).gid       = gid;

        let comm_ptr = (*event).comm.as_mut_ptr();
        aya_ebpf::helpers::bpf_get_current_comm(comm_ptr as *mut _, 64)
            .map_err(|e| e)?;

        // syscalls/sys_enter_execve: args[0] = filename ptr (offset 16)
        let filename_ptr: *const u8 = ctx.read_at(16)?;
        let payload = &mut (*event).payload.exec as *mut ExecPayload;
        aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut (*payload).filename,
        ).map_err(|e| e)?;
    }

    entry.submit(0);
    Ok(0)
}

// ── openat 트레이스포인트 ─────────────────────────────────────
#[tracepoint]
pub fn handle_file_open(ctx: TracePointContext) -> u32 {
    match try_handle_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 1,
    }
}

fn try_handle_file_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = (pid_tgid >> 32) as u32;
    let ppid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut entry = match EVENTS.reserve::<RawEvent>(0) {
        Some(e) => e,
        None    => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).kind      = EventKind::FileOpen;
        (*event).timestamp = bpf_ktime_get_ns();
        (*event).pid       = pid;
        (*event).ppid      = ppid;
        (*event).uid       = uid;
        (*event).gid       = gid;

        let comm_ptr = (*event).comm.as_mut_ptr();
        aya_ebpf::helpers::bpf_get_current_comm(comm_ptr as *mut _, 64)
            .map_err(|e| e)?;

        // syscalls/sys_enter_openat: args[1] = filename ptr (offset 24), args[2] = flags (offset 32)
        let filename_ptr: *const u8 = ctx.read_at(24)?;
        let flags: u32              = ctx.read_at(32)?;

        let payload = &mut (*event).payload.file;
        aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut (*payload).path,
        ).map_err(|e| e)?;
        (*payload).flags = flags;
    }

    entry.submit(0);
    Ok(0)
}

// ── connect 트레이스포인트 ────────────────────────────────────
#[tracepoint]
pub fn handle_net_connect(ctx: TracePointContext) -> u32 {
    match try_handle_net_connect(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 1,
    }
}

fn try_handle_net_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = (pid_tgid >> 32) as u32;
    let ppid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut entry = match EVENTS.reserve::<RawEvent>(0) {
        Some(e) => e,
        None    => return Ok(0),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).kind      = EventKind::NetConnect;
        (*event).timestamp = bpf_ktime_get_ns();
        (*event).pid       = pid;
        (*event).ppid      = ppid;
        (*event).uid       = uid;
        (*event).gid       = gid;

        let comm_ptr = (*event).comm.as_mut_ptr();
        aya_ebpf::helpers::bpf_get_current_comm(comm_ptr as *mut _, 64)
            .map_err(|e| e)?;

        // syscalls/sys_enter_connect: args[1] = sockaddr ptr (offset 24)
        let sockaddr_ptr: *const u8 = ctx.read_at(24)?;

        // sockaddr_in layout: [u16 family][u16 port big-endian][u32 addr]
        let port: u16 = aya_ebpf::helpers::bpf_probe_read_kernel(
            (sockaddr_ptr as usize + 2) as *const u16
        ).map_err(|e| e)?;
        let addr: u32 = aya_ebpf::helpers::bpf_probe_read_kernel(
            (sockaddr_ptr as usize + 4) as *const u32
        ).map_err(|e| e)?;

        let payload = &mut (*event).payload.net;
        payload.dst_ip   = addr;
        payload.dst_port = u16::from_be(port);
        payload.proto    = 6; // TCP
    }

    entry.submit(0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
