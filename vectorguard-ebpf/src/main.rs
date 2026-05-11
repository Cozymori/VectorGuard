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
        zero_exec_payload(event);

        // sys_enter_execve args: filename (16), argv (24), envp (32)
        if let Ok(filename_ptr) = ctx.read_at::<u64>(16) {
            if filename_ptr != 0 {
                let _ = bpf_probe_read_user_str_bytes(
                    filename_ptr as *const u8,
                    &mut (*event).payload.exec.filename,
                );
            }
        }
        if let Ok(argv_ptr) = ctx.read_at::<u64>(24) {
            if argv_ptr != 0 {
                fill_argv(event, argv_ptr);
            }
        }
    }

    entry.submit(0);

    if should_block {
        unsafe { bpf_send_signal(9) };
    }

    Ok(0)
}

#[inline(always)]
unsafe fn zero_exec_payload(event: *mut RawEvent) {
    unsafe {
        let mut k = 0usize;
        while k < 256 { (*event).payload.exec.filename[k] = 0; k += 1; }
        let mut k = 0usize;
        while k < 512 { (*event).payload.exec.argv[k] = 0; k += 1; }
    }
}

/// Read argv[1] into the event's argv buffer (argv[0] duplicates filename).
/// Reading only one argument keeps the eBPF program simple and verifier-
/// friendly. argv[1] alone is enough for typical signals like a URL passed
/// to wget or the first token of `sh -c "<cmd>"`.
#[inline(always)]
unsafe fn fill_argv(event: *mut RawEvent, argv_ptr: u64) {
    unsafe {
        let mut ptr_buf = [0u8; 8];
        let p_addr = argv_ptr + 8;
        if bpf_probe_read_user_buf(p_addr as *const u8, &mut ptr_buf).is_err() {
            return;
        }
        let arg_ptr = u64::from_ne_bytes(ptr_buf);
        if arg_ptr == 0 {
            return;
        }
        let _ = bpf_probe_read_user_str_bytes(
            arg_ptr as *const u8,
            &mut (*event).payload.exec.argv,
        );
    }
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

    // Read the larger sockaddr_in6 (28 bytes); sockaddr_in (16) fits in the
    // same buffer and we'll only read the v4 prefix when family == AF_INET.
    let mut sa_buf = [0u8; 28];
    unsafe {
        if bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sa_buf).is_err() {
            return Ok(0);
        }
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    let dst_port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let mut dst_addr = [0u8; 16];
    let family_byte: u8 = match family {
        2 => {
            // sockaddr_in: addr at offset 4..8
            dst_addr[0] = sa_buf[4];
            dst_addr[1] = sa_buf[5];
            dst_addr[2] = sa_buf[6];
            dst_addr[3] = sa_buf[7];
            4
        }
        10 => {
            // sockaddr_in6: sin6_addr at offset 8..24
            let mut i = 0usize;
            while i < 16 {
                dst_addr[i] = sa_buf[8 + i];
                i += 1;
            }
            6
        }
        _ => return Ok(0),
    };

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

        (*event).payload.net.dst_port = dst_port;
        (*event).payload.net.proto    = 6; // TCP
        (*event).payload.net.family   = family_byte;
        let mut i = 0usize;
        while i < 16 {
            (*event).payload.net.dst_addr[i] = dst_addr[i];
            i += 1;
        }
    }

    entry.submit(0);

    if should_block {
        unsafe { bpf_send_signal(9) };
    }

    Ok(0)
}

/// Preventive exec block. Runs at `bprm_check_security` (after the new
/// binary is resolved, before its address space is installed) and denies
/// the call when the caller's comm or UID is in our blocklists.
///
/// Returns `-EPERM` (-1) to abort the syscall. Unlike the tracepoint
/// SIGKILL path, the original process survives — execve just fails with
/// EPERM.
#[lsm(hook = "bprm_check_security")]
pub fn lsm_exec(_ctx: LsmContext) -> i32 {
    let comm16 = get_comm();
    if comm_is_blocked(&comm16) {
        return -1;
    }
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    if uid_is_blocked(uid) {
        return -1;
    }
    0
}

/// Preventive file_open block placeholder.
///
/// Real path-prefix blocking requires resolving the file's path or inode
/// inside the kernel. aya-ebpf 0.1.0 does not expose `bpf_d_path` through
/// its high-level API, and reading `struct file` fields without BTF/CO-RE
/// is brittle across kernels. Until we add raw helper bindings, path-based
/// blocking remains detect-and-kill via the openat tracepoint.
#[lsm(hook = "file_open")]
pub fn lsm_file_open(_ctx: LsmContext) -> i32 {
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
