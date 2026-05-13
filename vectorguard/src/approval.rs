//! AI advisor approval workflow.
//!
//! Proposed rules are written to `pending_dir` as one TOML file per rule. A
//! reviewer (TUI or CLI) promotes them to `approved_dir` (the daemon's
//! `rules_path`) under an `ai-approved-*.toml` filename, where the regular
//! hot-reload picks them up. A background reaper deletes approved files whose
//! mtime is older than `approval_ttl_secs`.
//!
//! In `auto` approval mode, `stage_auto` skips `pending_dir` and writes
//! directly into `approved_dir` — the TTL reaper still applies.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::fast_path::rules::{Rule, RuleSet};

#[derive(Clone)]
pub struct ApprovalStore {
    pub pending_dir:  PathBuf,
    pub approved_dir: PathBuf,
}

pub struct PendingItem {
    pub id:         String,
    pub path:       PathBuf,
    pub rule:       Rule,
    pub created_at: SystemTime,
}

impl ApprovalStore {
    pub fn new(pending_dir: impl Into<PathBuf>, approved_dir: impl Into<PathBuf>) -> Self {
        Self {
            pending_dir:  pending_dir.into(),
            approved_dir: approved_dir.into(),
        }
    }

    /// Stage a rule for manual review. Returns the id (filename stem).
    pub fn stage_pending(&self, rule: &Rule) -> Result<String> {
        std::fs::create_dir_all(&self.pending_dir)
            .with_context(|| format!("create_dir_all {}", self.pending_dir.display()))?;
        let id = make_id(&rule.name);
        let path = self.pending_dir.join(format!("{}.toml", id));
        write_rule(&path, rule)?;
        info!("approval: staged pending {}", path.display());
        Ok(id)
    }

    /// Stage a rule directly into the approved directory (auto mode). The
    /// reaper still removes it after the TTL elapses.
    pub fn stage_auto(&self, rule: &Rule) -> Result<String> {
        std::fs::create_dir_all(&self.approved_dir)
            .with_context(|| format!("create_dir_all {}", self.approved_dir.display()))?;
        let id = make_id(&rule.name);
        let path = self.approved_dir.join(format!("ai-approved-{}.toml", id));
        write_rule(&path, rule)?;
        info!("approval: auto-approved {}", path.display());
        Ok(id)
    }

    /// List pending proposals oldest-first. Malformed files are skipped with a warning.
    pub fn list_pending(&self) -> Result<Vec<PendingItem>> {
        let mut items = Vec::new();
        if !self.pending_dir.exists() {
            return Ok(items);
        }
        for entry in std::fs::read_dir(&self.pending_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => { warn!("approval: read {} failed: {}", path.display(), e); continue; }
            };
            let rs: RuleSet = match toml::from_str(&content) {
                Ok(r)  => r,
                Err(e) => { warn!("approval: parse {} failed: {}", path.display(), e); continue; }
            };
            let Some(rule) = rs.rules.into_iter().next() else { continue; };
            let id = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let created_at = entry.metadata()
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| SystemTime::now());
            items.push(PendingItem { id, path, rule, created_at });
        }
        items.sort_by_key(|i| i.created_at);
        Ok(items)
    }

    /// Promote a pending file to approved. The original is removed.
    pub fn approve(&self, id: &str) -> Result<PathBuf> {
        let src = self.pending_dir.join(format!("{}.toml", id));
        if !src.exists() {
            anyhow::bail!("pending id not found: {}", id);
        }
        std::fs::create_dir_all(&self.approved_dir)?;
        let dst = self.approved_dir.join(format!("ai-approved-{}.toml", id));
        std::fs::rename(&src, &dst)
            .with_context(|| format!("rename {} -> {}", src.display(), dst.display()))?;
        info!("approval: approved {}", dst.display());
        Ok(dst)
    }

    /// Discard a pending proposal.
    pub fn reject(&self, id: &str) -> Result<()> {
        let src = self.pending_dir.join(format!("{}.toml", id));
        if !src.exists() {
            anyhow::bail!("pending id not found: {}", id);
        }
        std::fs::remove_file(&src)?;
        info!("approval: rejected {}", id);
        Ok(())
    }

    /// Remove `ai-approved-*.toml` files older than `ttl`. Mtime-based.
    /// Returns the number of files removed.
    pub fn reap_expired(&self, ttl: Duration) -> Result<usize> {
        let mut count = 0;
        if !self.approved_dir.exists() {
            return Ok(0);
        }
        let now = SystemTime::now();
        for entry in std::fs::read_dir(&self.approved_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("ai-approved-") || !name_str.ends_with(".toml") {
                continue;
            }
            let meta = entry.metadata()?;
            let modified = match meta.modified() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if now.duration_since(modified).map(|age| age >= ttl).unwrap_or(false) {
                let path = entry.path();
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!("approval: failed to remove expired {}: {}", path.display(), e);
                } else {
                    info!("approval: reaped expired {}", path.display());
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

/// Periodically reap expired approved files. Runs until cancelled.
pub fn spawn_reaper(
    store:    ApprovalStore,
    interval: Duration,
    ttl:      Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval.max(Duration::from_secs(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;  // skip the immediate first tick
        loop {
            tick.tick().await;
            match store.reap_expired(ttl) {
                Ok(n) if n > 0 => debug!("approval: reaper removed {} files", n),
                Ok(_)          => {}
                Err(e)         => warn!("approval: reaper error: {}", e),
            }
        }
    })
}

fn make_id(rule_name: &str) -> String {
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", ts_ns, sanitize(rule_name))
}

fn sanitize(s: &str) -> String {
    let cleaned: String = s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    if cleaned.is_empty() { "rule".into() } else { cleaned }
}

fn write_rule(path: &std::path::Path, rule: &Rule) -> Result<()> {
    let rs = RuleSet { rules: vec![rule.clone()] };
    let body = toml::to_string_pretty(&rs)
        .context("serialize rule to TOML")?;
    let header = "# Auto-generated by VectorGuard AI Advisor — review or remove as needed\n\n";
    std::fs::write(path, format!("{}{}", header, body))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fast_path::rules::RuleAction;
    use std::thread::sleep;

    fn mkrule(name: &str) -> Rule {
        Rule {
            name:              name.into(),
            action:            RuleAction::Alert,
            description:       Some(format!("test rule {}", name)),
            match_process:     vec!["bash".into()],
            match_path_prefix: vec![],
            match_exec_path:   vec![],
            match_port:        vec![],
            match_uid:         None,
        }
    }

    fn mkstore() -> (ApprovalStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let pending  = tmp.path().join("pending");
        let approved = tmp.path().join("approved");
        let store = ApprovalStore::new(&pending, &approved);
        (store, tmp)
    }

    #[test]
    fn stage_pending_writes_file_and_returns_id() {
        let (store, _tmp) = mkstore();
        let id = store.stage_pending(&mkrule("test-one")).unwrap();
        let path = store.pending_dir.join(format!("{}.toml", id));
        assert!(path.exists());
        assert!(id.ends_with("-test-one"));
    }

    #[test]
    fn list_pending_returns_staged_rule_with_description() {
        let (store, _tmp) = mkstore();
        store.stage_pending(&mkrule("a")).unwrap();
        let items = store.list_pending().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].rule.name, "a");
        assert_eq!(items[0].rule.description.as_deref(), Some("test rule a"));
    }

    #[test]
    fn list_pending_sorts_oldest_first() {
        let (store, _tmp) = mkstore();
        store.stage_pending(&mkrule("first")).unwrap();
        sleep(Duration::from_millis(20));
        store.stage_pending(&mkrule("second")).unwrap();
        let items = store.list_pending().unwrap();
        assert!(items[0].rule.name == "first");
        assert!(items[1].rule.name == "second");
    }

    #[test]
    fn approve_moves_to_approved_dir_with_prefix() {
        let (store, _tmp) = mkstore();
        let id = store.stage_pending(&mkrule("z")).unwrap();
        let dst = store.approve(&id).unwrap();
        assert!(!store.pending_dir.join(format!("{}.toml", id)).exists());
        assert!(dst.exists());
        assert!(dst.file_name().unwrap().to_string_lossy().starts_with("ai-approved-"));
    }

    #[test]
    fn reject_removes_pending_file() {
        let (store, _tmp) = mkstore();
        let id = store.stage_pending(&mkrule("x")).unwrap();
        store.reject(&id).unwrap();
        assert!(!store.pending_dir.join(format!("{}.toml", id)).exists());
    }

    #[test]
    fn reject_unknown_id_errors() {
        let (store, _tmp) = mkstore();
        assert!(store.reject("does-not-exist").is_err());
    }

    #[test]
    fn stage_auto_writes_directly_to_approved() {
        let (store, _tmp) = mkstore();
        let id = store.stage_auto(&mkrule("auto")).unwrap();
        let path = store.approved_dir.join(format!("ai-approved-{}.toml", id));
        assert!(path.exists());
        assert!(store.list_pending().unwrap().is_empty());
    }

    #[test]
    fn reap_expired_removes_old_files_only() {
        let (store, _tmp) = mkstore();
        store.stage_auto(&mkrule("fresh")).unwrap();
        // ttl=0 means everything is "expired"
        let n = store.reap_expired(Duration::from_secs(0)).unwrap();
        assert_eq!(n, 1);
        // ttl=large means nothing is removed
        store.stage_auto(&mkrule("survives")).unwrap();
        let n2 = store.reap_expired(Duration::from_secs(3600)).unwrap();
        assert_eq!(n2, 0);
    }

    #[test]
    fn reap_ignores_non_ai_approved_files() {
        let (store, _tmp) = mkstore();
        std::fs::create_dir_all(&store.approved_dir).unwrap();
        let unrelated = store.approved_dir.join("default.toml");
        std::fs::write(&unrelated, "# unrelated rule file").unwrap();
        let n = store.reap_expired(Duration::from_secs(0)).unwrap();
        assert_eq!(n, 0);
        assert!(unrelated.exists());
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(sanitize("foo/bar baz"), "foo-bar-baz");
        assert_eq!(sanitize("ok_name-1"), "ok_name-1");
        assert_eq!(sanitize(""), "rule");
    }
}
