use anyhow::Result;
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch, RwLock};
use tracing::{info, warn};

use crate::config::Config;

/// Watch config.toml and the rules directory for changes.
/// On each change:
///   1. Parses the new config and updates the shared Arc<RwLock<Config>>
///   2. Sends the new config via `reload_tx` so the pipeline can rebuild components
///
/// Rules directory changes send the current config (triggering a FastPath rebuild
/// that picks up the new/modified rule files) without requiring config.toml to change.
pub async fn watch(
    config_path: &str,
    config:      Arc<RwLock<Config>>,
    reload_tx:   watch::Sender<Config>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<()>(4);

    let tx_clone = tx.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, _>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                    let _ = tx_clone.blocking_send(());
                }
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_millis(500)),
    )?;

    watcher.watch(Path::new(config_path), RecursiveMode::NonRecursive)?;
    info!("Hot reload watch started: {}", config_path);

    // Also watch the rules directory derived from the config
    let rules_path = {
        let cfg = config.read().await;
        cfg.fast_path.rules_path.clone()
    };
    if Path::new(&rules_path).is_dir() {
        watcher.watch(Path::new(&rules_path), RecursiveMode::NonRecursive)?;
        info!("Hot reload watch started: {}", rules_path);
    }

    // Keep watcher alive inside the task so it is not dropped
    tokio::spawn(async move { let _w = watcher; std::future::pending::<()>().await });

    while rx.recv().await.is_some() {
        // Drain any rapid successive events
        while rx.try_recv().is_ok() {}

        match Config::load(config_path) {
            Ok(new_cfg) => {
                *config.write().await = new_cfg.clone();
                let _ = reload_tx.send(new_cfg);
                info!("config reloaded successfully");
            }
            Err(e) => {
                // config.toml may not have changed — send current config to trigger
                // a rules reload anyway (rules dir change)
                let current = config.read().await.clone();
                let _ = reload_tx.send(current);
                warn!("config.toml unchanged or invalid ({}); reloading rules only", e);
            }
        }
    }

    Ok(())
}
