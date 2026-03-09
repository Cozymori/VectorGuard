#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint, lsm},
    maps::{RingBuf, HashMap},
    programs::{TracePointContext, LsmContext},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_send_signal},
};
use vectorguard_common::{EventKind, ExecPayload, RawEvent};

// ── Ring Buffer: eBPF → userspace ────────────────────────────
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1MB

// ── Blocking Maps: written by userspace Enforcer ──────────────
/// Blocked comm names — key: first 16 bytes of comm (null-padded)
#[map]
static BLOCKED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Blocked destination ports
#[map]
static BLOCKED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

/// Blocked UIDs
#[map]
static BLOCKED_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// ── Helper: check if current comm is blocked ──────────────────
#[inline(always)]
fn comm_is_blocked(comm: &[u8; 64]) -> bool {
    let mut key = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        if comm[i] == 0 { break; }
        key[i] = comm[i];
        i += 1;
    }
    unsafe { BLOCKED_COMMS.get(&key).is_some() }
}

// ── Helper: check if current uid is blocked ───────────────────
#[inline(always)]
fn uid_is_blocked(uid: u32) -> bool {
    unsafe { BLOCKED_UIDS.get(&uid).is_some() }
}

// ── execve tracepoint ────────────────────────────────────────
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
    let mut blocked: u8 = 0;

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

        // Check blocking rules against comm and uid
        if comm_is_blocked(&(*event).comm) || uid_is_blocked(uid) {
            bpf_send_signal(9); // SIGKILL
            blocked = 1;
        }

        // syscalls/sys_enter_execve: args[0] = filename ptr (offset 16)
        let filename_ptr: *const u8 = ctx.read_at(16)?;
        let payload = &mut (*event).payload.exec as *mut ExecPayload;
        aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut (*payload).filename,
        ).map_err(|e| e)?;

        (*event).blocked = blocked;
    }

    entry.submit(0);
    Ok(0)
}

// ── openat tracepoint ───────────────────────────────────────
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
    let mut blocked: u8 = 0;

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

        // Check blocking rules
        if comm_is_blocked(&(*event).comm) || uid_is_blocked(uid) {
            bpf_send_signal(9); // SIGKILL
            blocked = 1;
        }

        // syscalls/sys_enter_openat: args[1] = filename ptr (offset 24), args[2] = flags (offset 32)
        let filename_ptr: *const u8 = ctx.read_at(24)?;
        let flags: u32              = ctx.read_at(32)?;

        let payload = &mut (*event).payload.file;
        aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut (*payload).path,
        ).map_err(|e| e)?;
        (*payload).flags = flags;

        (*event).blocked = blocked;
    }

    entry.submit(0);
    Ok(0)
}

// ── connect tracepoint ──────────────────────────────────────
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
    let mut blocked: u8 = 0;

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

        let dst_port = u16::from_be(port);

        // Check blocking rules: comm, uid, or destination port
        if comm_is_blocked(&(*event).comm) || uid_is_blocked(uid)
            || BLOCKED_PORTS.get(&dst_port).is_some()
        {
            bpf_send_signal(9); // SIGKILL
            blocked = 1;
        }

        let payload = &mut (*event).payload.net;
        payload.dst_ip   = addr;
        payload.dst_port = dst_port;
        payload.proto    = 6; // TCP

        (*event).blocked = blocked;
    }

    entry.submit(0);
    Ok(0)
}

// ── LSM hook: bprm_check_security (exec) ────────────────────
// Returns -EPERM to proactively block exec before the process starts.
// Complements the tracepoint (which fires concurrently / reactively).
#[lsm(hook = "bprm_check_security")]
pub fn lsm_exec(ctx: LsmContext) -> i32 {
    match try_lsm_exec(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 0, // fail-open on error
    }
}

fn try_lsm_exec(_ctx: &LsmContext) -> Result<i32, i64> {
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;

    if uid_is_blocked(uid) {
        return Ok(-1); // -EPERM
    }

    let mut comm = [0u8; 64];
    unsafe {
        aya_ebpf::helpers::bpf_get_current_comm(comm.as_mut_ptr() as *mut _, 64)
            .map_err(|e| e)?;
    }
    if comm_is_blocked(&comm) {
        return Ok(-1); // -EPERM
    }

    Ok(0)
}

// ── LSM hook: file_open ──────────────────────────────────────
// Returns -EPERM to proactively block sensitive file opens.
#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    match try_lsm_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 0, // fail-open on error
    }
}

fn try_lsm_file_open(_ctx: &LsmContext) -> Result<i32, i64> {
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;

    if uid_is_blocked(uid) {
        return Ok(-1); // -EPERM
    }

    let mut comm = [0u8; 64];
    unsafe {
        aya_ebpf::helpers::bpf_get_current_comm(comm.as_mut_ptr() as *mut _, 64)
            .map_err(|e| e)?;
    }
    if comm_is_blocked(&comm) {
        return Ok(-1); // -EPERM
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
