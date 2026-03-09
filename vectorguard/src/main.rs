#[cfg(target_os = "linux")]
mod collector;
#[cfg(target_os = "linux")]
mod enforcer;
mod config;
mod event;
mod adapter;
mod fast_path;
mod hotreload;
mod scope;
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
                        // Initialize kernel-level enforcer from eBPF blocking maps
                        match enforcer::Enforcer::from_ebpf(&mut ebpf) {
                            Ok(mut enf) => {
                                // Load block rules from fast path rule files into eBPF maps
                                let fp_cfg = cfg_snap.fast_path.clone();
                                let tmp_fp = fast_path::FastPath::new(&fp_cfg);
                                if let Err(e) = enf.load_rules(tmp_fp.rules()) {
                                    tracing::warn!("Enforcer rule load failed: {}", e);
                                }
                                // Keep enforcer alive for the duration of the collector task
                                let _enf = enf;
                            }
                            Err(e) => tracing::warn!("Enforcer init failed: {}", e),
                        }
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

    // ── Pipeline Component Initialization ────────────────────
    let cfg_snap = cfg.read().await.clone();
    let scope_filter = scope::ScopeFilter::new(&cfg_snap.scope);
    let fast_path    = fast_path::FastPath::new(&cfg_snap.fast_path);
    let slow_path    = slow_path::SlowPath::new(&cfg_snap.slow_path).await;

    // ── Event Processing Pipeline Task ────────────────────────
    tokio::spawn(run_pipeline(raw_rx, proc_tx, scope_filter, fast_path, slow_path));

    // ── Run TUI ───────────────────────────────────────────────
    let config_text = std::fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let app = tui::App::new(config_text);
    tui::run(app, Some(proc_rx)).await
}

/// Event processing pipeline: Scope filter → Fast Path → Slow Path → TUI
async fn run_pipeline(
    mut raw_rx:   mpsc::Receiver<NormalizedEvent>,
    proc_tx:      mpsc::Sender<NormalizedEvent>,
    scope_filter: scope::ScopeFilter,
    fast_path:    fast_path::FastPath,
    slow_path:    slow_path::SlowPath,
) {
    while let Some(mut ev) = raw_rx.recv().await {
        // Scope filter: skip events from unmonitored processes
        if !scope_filter.allows(&ev) {
            continue;
        }

        // Fast Path: synchronous rule evaluation
        fast_path.evaluate(&mut ev);

        // Slow Path: async vector similarity anomaly detection
        slow_path.analyze(&mut ev).await;

        if proc_tx.send(ev).await.is_err() {
            break; // TUI exited
        }
    }
}
