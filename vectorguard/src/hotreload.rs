use anyhow::Result;
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::config::Config;

/// Watch config.toml for changes and apply the new Config
pub async fn watch(
    config_path: &str,
    config: Arc<RwLock<Config>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<()>(1);

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, _>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    let _ = tx.blocking_send(());
                }
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_millis(500)),
    )?;

    watcher.watch(Path::new(config_path), RecursiveMode::NonRecursive)?;
    info!("Hot reload watch started: {}", config_path);

    // Keep watcher alive inside the task so it is not dropped
    tokio::spawn(async move { let _w = watcher; std::future::pending::<()>().await });

    while rx.recv().await.is_some() {
        match Config::load(config_path) {
            Ok(new_cfg) => {
                *config.write().await = new_cfg;
                info!("config.toml reloaded successfully");
            }
            Err(e) => warn!("Failed to reload config.toml (keeping existing config): {}", e),
        }
    }

    Ok(())
}
