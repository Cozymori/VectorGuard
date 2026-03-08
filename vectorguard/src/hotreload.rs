use anyhow::Result;
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::config::Config;

/// config.toml 변경 감지 → 새 Config 전달
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
    info!("핫 리로드 감시 시작: {}", config_path);

    // watcher가 드랍되지 않도록 task 안에 유지
    tokio::spawn(async move { let _w = watcher; std::future::pending::<()>().await });

    while rx.recv().await.is_some() {
        match Config::load(config_path) {
            Ok(new_cfg) => {
                *config.write().await = new_cfg;
                info!("config.toml 리로드 완료");
            }
            Err(e) => warn!("config.toml 리로드 실패 (기존 설정 유지): {}", e),
        }
    }

    Ok(())
}
