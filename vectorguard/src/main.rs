#[cfg(target_os = "linux")]
mod collector;
mod config;
mod event;
mod adapter;
mod fast_path;
mod hotreload;
mod slow_path;
mod tui;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

use config::AdapterBackend;
use event::NormalizedEvent;

const CONFIG_PATH: &str = "config.toml";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = config::Config::load(CONFIG_PATH)?;
    info!("VectorGuard starting | adapter={:?}", cfg.adapter.backend);

    let cfg = Arc::new(RwLock::new(cfg));

    // ── Hot Reload ────────────────────────────────────────────
    if cfg.read().await.system.hot_reload {
        let cfg_clone = Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(e) = hotreload::watch(CONFIG_PATH, cfg_clone).await {
                tracing::error!("Hot reload error: {}", e);
            }
        });
    }

    // ── Event Pipeline Channels ───────────────────────────────
    // raw_tx/rx : collector → processing pipeline
    // proc_tx/rx: processing pipeline → TUI
    let (raw_tx, raw_rx) = mpsc::channel::<NormalizedEvent>(4096);
    let (proc_tx, proc_rx) = mpsc::channel::<NormalizedEvent>(4096);

    // ── Start Event Collector ─────────────────────────────────
    {
        let cfg_snap = cfg.read().await.clone();

        #[cfg(target_os = "linux")]
        if cfg_snap.adapter.backend == AdapterBackend::NativeEbpf {
            let tx = raw_tx.clone();
            tokio::spawn(async move {
                match collector::load_ebpf() {
                    Ok(mut ebpf) => {
                        if let Err(e) = collector::run_collector(&mut ebpf, tx).await {
                            tracing::error!("eBPF collector error: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("eBPF load failed: {}", e),
                }
            });
            info!("Native eBPF collector started");
        }

        #[cfg(not(target_os = "linux"))]
        let _ = AdapterBackend::NativeEbpf; // suppress unused warning

        if cfg_snap.adapter.backend != AdapterBackend::NativeEbpf {
            let adapter = adapter::create(&cfg_snap);
            let tx = raw_tx.clone();
            tokio::spawn(async move {
                adapter::run(adapter, tx).await;
            });
            info!("Adapter started: {:?}", cfg_snap.adapter.backend);
        }
    }
    drop(raw_tx); // spawned tasks hold their own copies

    // ── Fast Path Initialization ──────────────────────────────
    let fast_path = {
        let cfg_snap = cfg.read().await;
        fast_path::FastPath::new(&cfg_snap.fast_path)
    };

    // ── Slow Path Initialization ──────────────────────────────
    let slow_path = {
        let cfg_snap = cfg.read().await;
        slow_path::SlowPath::new(&cfg_snap.slow_path).await
    };

    // ── Event Processing Pipeline Task ────────────────────────
    tokio::spawn(run_pipeline(raw_rx, proc_tx, fast_path, slow_path));

    // ── Run TUI ───────────────────────────────────────────────
    let config_text = std::fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let app = tui::App::new(config_text);
    tui::run(app, Some(proc_rx)).await
}

/// Event processing pipeline: Fast Path → Slow Path → forward to TUI channel
async fn run_pipeline(
    mut raw_rx:  mpsc::Receiver<NormalizedEvent>,
    proc_tx:     mpsc::Sender<NormalizedEvent>,
    fast_path:   fast_path::FastPath,
    slow_path:   slow_path::SlowPath,
) {
    while let Some(mut ev) = raw_rx.recv().await {
        // Phase 2: Fast Path (synchronous, rule evaluation)
        fast_path.evaluate(&mut ev);

        // Phase 3: Slow Path (asynchronous, vector similarity)
        slow_path.analyze(&mut ev).await;

        if proc_tx.send(ev).await.is_err() {
            break; // TUI exited
        }
    }
}
