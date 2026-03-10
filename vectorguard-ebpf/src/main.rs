#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint, lsm},
    maps::{RingBuf, HashMap},
    programs::{TracePointContext, LsmContext},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_current_comm, bpf_ktime_get_ns, bpf_send_signal,
        bpf_probe_read_user_str_bytes, bpf_probe_read_user_buf,
    },
};
use vectorguard_common::{EventKind, RawEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static BLOCKED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

#[map]
static BLOCKED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[map]
static BLOCKED_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

#[inline(always)]
fn comm_is_blocked(comm: &[u8; 16]) -> bool {
    unsafe { BLOCKED_COMMS.get(comm).is_some() }
}

#[inline(always)]
fn uid_is_blocked(uid: u32) -> bool {
    unsafe { BLOCKED_UIDS.get(&uid).is_some() }
}

#[inline(always)]
fn get_comm() -> [u8; 16] {
    bpf_get_current_comm().unwrap_or([0u8; 16])
}

#[inline(always)]
unsafe fn fill_comm(event: *mut RawEvent, comm16: &[u8; 16]) {
    unsafe {
        let mut i = 0usize;
        while i < 16 {
            (*event).comm[i] = comm16[i];
            i += 1;
        }
    }
}

// ── Exec handler ──
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

    let comm16 = get_comm();
    let should_block = comm_is_blocked(&comm16) || uid_is_blocked(uid);

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
        (*event).blocked   = if should_block { 1 } else { 0 };

        fill_comm(event, &comm16);

        // Read exec filename from tracepoint args
        // sys_enter_execve format: offset 16 = filename pointer
        if let Ok(filename_ptr) = ctx.read_at::<u64>(16) {
            if filename_ptr != 0 {
                let _ = bpf_probe_read_user_str_bytes(
                    filename_ptr as *const u8,
                    &mut (*event).payload.exec.filename,
                );
            }
        }
    }

    entry.submit(0);

    if should_block {
        unsafe { bpf_send_signal(9) };
    }

    Ok(0)
}

// ── File open handler ──
#[tracepoint]
pub fn handle_file_open(ctx: TracePointContext) -> u32 {
    match try_handle_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 0,
    }
}

fn try_handle_file_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = (pid_tgid >> 32) as u32;
    let ppid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm16 = get_comm();

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
        (*event).blocked   = 0;

        fill_comm(event, &comm16);

        // sys_enter_openat format: offset 24 = filename pointer, offset 32 = flags
        if let Ok(filename_ptr) = ctx.read_at::<u64>(24) {
            if filename_ptr != 0 {
                let _ = bpf_probe_read_user_str_bytes(
                    filename_ptr as *const u8,
                    &mut (*event).payload.file.path,
                );
            }
        }
        if let Ok(flags) = ctx.read_at::<u64>(32) {
            (*event).payload.file.flags = flags as u32;
        }
    }

    entry.submit(0);
    Ok(0)
}

// ── Net connect handler ──
#[tracepoint]
pub fn handle_net_connect(ctx: TracePointContext) -> u32 {
    match try_handle_net_connect(&ctx) {
        Ok(ret) => ret,
        Err(_)  => 0,
    }
}

fn try_handle_net_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid  = (pid_tgid >> 32) as u32;
    let ppid = (pid_tgid & 0xFFFF_FFFF) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm16 = get_comm();

    // sys_enter_connect: offset 24 = sockaddr pointer, offset 32 = addrlen
    let addr_ptr = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) };
    if addr_ptr == 0 {
        return Ok(0);
    }

    // Read sockaddr_in from userspace (fixed-length, not string)
    let mut sa_buf = [0u8; 16];
    unsafe {
        if bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sa_buf).is_err() {
            return Ok(0);
        }
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    // AF_INET = 2
    if family != 2 {
        return Ok(0);
    }

    let dst_port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let dst_ip = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    let should_block = unsafe { BLOCKED_PORTS.get(&dst_port).is_some() };

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
        (*event).blocked   = if should_block { 1 } else { 0 };

        fill_comm(event, &comm16);

        (*event).payload.net.dst_ip   = dst_ip;
        (*event).payload.net.dst_port = dst_port;
        (*event).payload.net.proto    = 6; // TCP
    }

    entry.submit(0);

    if should_block {
        unsafe { bpf_send_signal(9) };
    }

    Ok(0)
}

#[lsm(hook = "bprm_check_security")]
pub fn lsm_exec(_ctx: LsmContext) -> i32 {
    0
}

#[lsm(hook = "file_open")]
pub fn lsm_file_open(_ctx: LsmContext) -> i32 {
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
