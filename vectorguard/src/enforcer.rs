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

use crate::fast_path::rules::{Rule, RuleAction};

/// Convert a process name string to the 16-byte comm key used in the eBPF map.
/// Names longer than 16 bytes are truncated; shorter names are zero-padded.
pub fn comm_key(name: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(16);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// The set of keys that should be installed in the kernel block maps for a
/// given rule list. Extracted so it can be unit-tested without the actual
/// eBPF map handles (which only exist on Linux).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockKeys {
    pub comms: Vec<[u8; 16]>,
    pub ports: Vec<u16>,
    pub uids:  Vec<u32>,
}

pub fn compute_block_keys(rules: &[Rule]) -> BlockKeys {
    let mut keys = BlockKeys::default();
    for rule in rules.iter().filter(|r| r.action == RuleAction::Block) {
        for proc in &rule.match_process {
            keys.comms.push(comm_key(proc));
        }
        for &port in &rule.match_port {
            keys.ports.push(port);
        }
        if let Some(uid) = rule.match_uid {
            keys.uids.push(uid);
        }
    }
    keys
}

#[cfg(target_os = "linux")]
pub use linux_impl::Enforcer;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use anyhow::{Context, Result};
    use aya::{maps::HashMap as AyaHashMap, Ebpf};
    use tracing::info;

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
            self.clear()?;

            let keys = compute_block_keys(rules);

            for k in &keys.comms { self.comms.insert(*k, 1u8, 0)?; }
            for &p in &keys.ports { self.ports.insert(p, 1u8, 0)?; }
            for &u in &keys.uids { self.uids.insert(u, 1u8, 0)?; }

            info!(
                "Enforcer loaded: {} comm blocks, {} port blocks, {} uid blocks",
                keys.comms.len(), keys.ports.len(), keys.uids.len(),
            );
            Ok(())
        }

        fn clear(&mut self) -> Result<()> {
            // Collect keys first to avoid borrow conflicts.
            let comm_keys: Vec<[u8; 16]> = self.comms.keys().filter_map(|r| r.ok()).collect();
            for k in comm_keys { let _ = self.comms.remove(&k); }

            let port_keys: Vec<u16> = self.ports.keys().filter_map(|r| r.ok()).collect();
            for k in port_keys { let _ = self.ports.remove(&k); }

            let uid_keys: Vec<u32> = self.uids.keys().filter_map(|r| r.ok()).collect();
            for k in uid_keys { let _ = self.uids.remove(&k); }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fast_path::rules::{Rule, RuleAction};

    fn block_rule(name: &str) -> Rule {
        Rule {
            name:              name.into(),
            action:            RuleAction::Block,
            description:       None,
            match_process:     vec![],
            match_path_prefix: vec![],
            match_exec_path:   vec![],
            match_port:        vec![],
            match_uid:         None,
        }
    }

    #[test]
    fn comm_key_short_name_is_zero_padded() {
        let k = comm_key("sh");
        assert_eq!(&k[..2], b"sh");
        assert!(k[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn comm_key_long_name_is_truncated_to_16_bytes() {
        let k = comm_key("aaaaaaaaaaaaaaaaaaaa"); // 20 'a's
        assert_eq!(k, [b'a'; 16]);
    }

    #[test]
    fn comm_key_exactly_16_bytes_fills_array() {
        let k = comm_key("0123456789abcdef");
        assert_eq!(&k[..], b"0123456789abcdef");
    }

    #[test]
    fn compute_block_keys_skips_non_block_rules() {
        let mut r1 = block_rule("a");
        r1.match_process = vec!["nginx".into()];
        let mut r2 = Rule { action: RuleAction::Alert, ..block_rule("b") };
        r2.match_process = vec!["sshd".into()];

        let keys = compute_block_keys(&[r1, r2]);
        assert_eq!(keys.comms.len(), 1);
        assert_eq!(&keys.comms[0][..5], b"nginx");
    }

    #[test]
    fn compute_block_keys_collects_ports_and_uids() {
        let mut r = block_rule("misc");
        r.match_port = vec![4444, 1337];
        r.match_uid  = Some(0);

        let keys = compute_block_keys(&[r]);
        assert_eq!(keys.ports, vec![4444, 1337]);
        assert_eq!(keys.uids, vec![0]);
    }

    #[test]
    fn compute_block_keys_handles_multiple_block_rules() {
        let mut r1 = block_rule("a");
        r1.match_process = vec!["nc".into(), "ncat".into()];
        let mut r2 = block_rule("b");
        r2.match_process = vec!["xmrig".into()];
        r2.match_uid     = Some(1000);

        let keys = compute_block_keys(&[r1, r2]);
        assert_eq!(keys.comms.len(), 3);
        assert_eq!(keys.uids, vec![1000]);
    }

    #[test]
    fn compute_block_keys_empty_on_no_block_rules() {
        let r = Rule { action: RuleAction::Log, ..block_rule("x") };
        let keys = compute_block_keys(&[r]);
        assert_eq!(keys, BlockKeys::default());
    }
}
