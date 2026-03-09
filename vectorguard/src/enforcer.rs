//! Kernel-level enforcer: populates eBPF blocking maps from Fast Path rules.
//!
//! The `Enforcer` owns references to three eBPF HashMaps:
//!   - `BLOCKED_COMMS` — process name → block (first 16 bytes of comm)
//!   - `BLOCKED_PORTS` — destination TCP port → block
//!   - `BLOCKED_UIDS`  — UID → block
//!
//! When the eBPF tracepoints or LSM hooks see a match in these maps,
//! they call `bpf_send_signal(SIGKILL)` (tracepoints) or return `-EPERM`
//! (LSM hooks), enforcing the policy in-kernel with zero userspace round-trip.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use aya::{maps::HashMap as AyaHashMap, Ebpf};
use tracing::{info, warn};

use crate::fast_path::rules::{Rule, RuleAction};

pub struct Enforcer {
    comms: AyaHashMap<aya::maps::MapData, [u8; 16], u8>,
    ports: AyaHashMap<aya::maps::MapData, u16, u8>,
    uids:  AyaHashMap<aya::maps::MapData, u32, u8>,
}

impl Enforcer {
    /// Take ownership of the blocking maps out of the loaded `Ebpf` handle.
    /// The eBPF programs continue to reference the same kernel maps via
    /// the kernel's reference-counting — this just transfers the fd to us.
    pub fn from_ebpf(ebpf: &mut Ebpf) -> Result<Self> {
        let comms = AyaHashMap::try_from(
            ebpf.take_map("BLOCKED_COMMS")
                .context("BLOCKED_COMMS map not found")?,
        )?;
        let ports = AyaHashMap::try_from(
            ebpf.take_map("BLOCKED_PORTS")
                .context("BLOCKED_PORTS map not found")?,
        )?;
        let uids = AyaHashMap::try_from(
            ebpf.take_map("BLOCKED_UIDS")
                .context("BLOCKED_UIDS map not found")?,
        )?;

        Ok(Self { comms, ports, uids })
    }

    /// Load blocking rules from the Fast Path rule set into the eBPF maps.
    /// Only rules with `action = Block` are installed.
    pub fn load_rules(&mut self, rules: &[Rule]) -> Result<()> {
        // Clear existing entries
        self.clear()?;

        let mut n_comms = 0u32;
        let mut n_ports = 0u32;
        let mut n_uids  = 0u32;

        for rule in rules.iter().filter(|r| r.action == RuleAction::Block) {
            // Block by process name (comm)
            for proc in &rule.match_process {
                let key = comm_key(proc);
                self.comms.insert(key, 1u8, 0)?;
                n_comms += 1;
            }

            // Block by destination port
            for &port in &rule.match_port {
                self.ports.insert(port, 1u8, 0)?;
                n_ports += 1;
            }

            // Block by UID
            if let Some(uid) = rule.match_uid {
                self.uids.insert(uid, 1u8, 0)?;
                n_uids += 1;
            }
        }

        info!(
            "Enforcer loaded: {} comm blocks, {} port blocks, {} uid blocks",
            n_comms, n_ports, n_uids
        );
        Ok(())
    }

    /// Block a specific process name immediately (e.g. after slow path anomaly).
    #[allow(dead_code)]
    pub fn block_comm(&mut self, comm: &str) {
        let key = comm_key(comm);
        if let Err(e) = self.comms.insert(key, 1u8, 0) {
            warn!("Failed to block comm '{}': {}", comm, e);
        } else {
            info!("Enforcer: blocked comm '{}'", comm);
        }
    }

    /// Block a specific UID immediately.
    #[allow(dead_code)]
    pub fn block_uid(&mut self, uid: u32) {
        if let Err(e) = self.uids.insert(uid, 1u8, 0) {
            warn!("Failed to block uid {}: {}", uid, e);
        } else {
            info!("Enforcer: blocked uid {}", uid);
        }
    }

    /// Block a destination port immediately.
    #[allow(dead_code)]
    pub fn block_port(&mut self, port: u16) {
        if let Err(e) = self.ports.insert(port, 1u8, 0) {
            warn!("Failed to block port {}: {}", port, e);
        } else {
            info!("Enforcer: blocked port {}", port);
        }
    }

    fn clear(&mut self) -> Result<()> {
        // Collect keys first to avoid borrow conflicts
        let comm_keys: Vec<[u8; 16]> = self.comms.keys().filter_map(|r| r.ok()).collect();
        for k in comm_keys { let _ = self.comms.remove(&k); }

        let port_keys: Vec<u16> = self.ports.keys().filter_map(|r| r.ok()).collect();
        for k in port_keys { let _ = self.ports.remove(&k); }

        let uid_keys: Vec<u32> = self.uids.keys().filter_map(|r| r.ok()).collect();
        for k in uid_keys { let _ = self.uids.remove(&k); }

        Ok(())
    }
}

/// Convert a process name string to the 16-byte comm key used in the eBPF map.
fn comm_key(name: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(16);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}
