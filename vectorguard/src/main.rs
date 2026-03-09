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
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, RwLock};
use tracing::info;

use config::AdapterBackend;
use event::NormalizedEvent;

const CONFIG_PATH: &str = "config.toml";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = config::Config::load(CONFIG_PATH)?;
    info!("VectorGuard starting | adapter={:?}", cfg.adapter.backend);

    let cfg_arc = Arc::new(RwLock::new(cfg.clone()));

    // ── Config Reload Broadcast Channel ──────────────────────────
    // Produced by hotreload::watch, consumed by run_pipeline for live reconfiguration.
    let (reload_tx, reload_rx) = watch::channel(cfg.clone());

    // ── Hot Reload ────────────────────────────────────────────────
    if cfg.system.hot_reload {
        let cfg_arc2 = Arc::clone(&cfg_arc);
        tokio::spawn(async move {
            if let Err(e) = hotreload::watch(CONFIG_PATH, cfg_arc2, reload_tx).await {
                tracing::error!("Hot reload error: {}", e);
            }
        });
    }

    // ── Shared Kernel Enforcer (Linux only) ───────────────────────
    // Initialized by the collector task, updated by run_pipeline on hot reload.
    #[cfg(target_os = "linux")]
    let enf_shared: Arc<Mutex<Option<enforcer::Enforcer>>> = Arc::new(Mutex::new(None));

    // ── Event Pipeline Channels ───────────────────────────────────
    let (raw_tx, raw_rx) = mpsc::channel::<NormalizedEvent>(4096);
    let (proc_tx, proc_rx) = mpsc::channel::<NormalizedEvent>(4096);

    // ── Start Event Collector ─────────────────────────────────────
    {
        let cfg_snap = cfg.clone();

        #[cfg(target_os = "linux")]
        if cfg_snap.adapter.backend == AdapterBackend::NativeEbpf {
            let tx = raw_tx.clone();
            let enf_arc = Arc::clone(&enf_shared);

            tokio::spawn(async move {
                match collector::load_ebpf() {
                    Ok(mut ebpf) => {
                        // Initialize kernel enforcer and populate from fast-path block rules
                        match enforcer::Enforcer::from_ebpf(&mut ebpf) {
                            Ok(mut enf) => {
                                let tmp_fp = fast_path::FastPath::new(&cfg_snap.fast_path);
                                if let Err(e) = enf.load_rules(tmp_fp.rules()) {
                                    tracing::warn!("Enforcer rule load failed: {}", e);
                                }
                                *enf_arc.lock().unwrap() = Some(enf);
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
    drop(raw_tx);

    // ── Pipeline Component Initialization ─────────────────────────
    let scope_filter = scope::ScopeFilter::new(&cfg.scope);
    let fast_path    = fast_path::FastPath::new(&cfg.fast_path);
    let slow_path    = slow_path::SlowPath::new(&cfg.slow_path).await;

    // ── Event Processing Pipeline Task ────────────────────────────
    #[cfg(target_os = "linux")]
    tokio::spawn(run_pipeline(
        raw_rx, proc_tx, scope_filter, fast_path, slow_path,
        reload_rx, Some(enf_shared),
    ));

    #[cfg(not(target_os = "linux"))]
    tokio::spawn(run_pipeline(
        raw_rx, proc_tx, scope_filter, fast_path, slow_path,
        reload_rx, None,
    ));

    // ── Run TUI ───────────────────────────────────────────────────
    let config_text = std::fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let app = tui::App::new(config_text);
    tui::run(app, Some(proc_rx)).await
}

/// Event processing pipeline with live hot-reload support.
///
/// On each config change received via `reload_rx`, the scope filter, fast path,
/// and slow path are rebuilt from the new config. On Linux, the kernel enforcer's
/// eBPF blocking maps are also repopulated with any new block rules (D).
async fn run_pipeline(
    mut raw_rx:   mpsc::Receiver<NormalizedEvent>,
    proc_tx:      mpsc::Sender<NormalizedEvent>,
    mut scope_filter: scope::ScopeFilter,
    mut fast_path:    fast_path::FastPath,
    mut slow_path:    slow_path::SlowPath,
    mut reload_rx:    watch::Receiver<config::Config>,
    #[cfg(target_os = "linux")]
    enf_opt: Option<Arc<Mutex<Option<enforcer::Enforcer>>>>,
    #[cfg(not(target_os = "linux"))]
    _enf_opt: Option<()>,
) {
    loop {
        tokio::select! {
            // ── Process incoming event ────────────────────────────
            ev = raw_rx.recv() => {
                let Some(mut ev) = ev else { break };

                if !scope_filter.allows(&ev) {
                    continue;
                }

                fast_path.evaluate(&mut ev);
                slow_path.analyze(&mut ev).await;

                if proc_tx.send(ev).await.is_err() {
                    break; // TUI exited
                }
            }

            // ── Hot reload: rebuild pipeline components ───────────
            Ok(()) = reload_rx.changed() => {
                let new_cfg = reload_rx.borrow().clone();
                tracing::info!("Pipeline reloading with new config");

                scope_filter = scope::ScopeFilter::new(&new_cfg.scope);
                fast_path    = fast_path::FastPath::new(&new_cfg.fast_path);
                slow_path    = slow_path::SlowPath::new(&new_cfg.slow_path).await;

                // D: push updated block rules into eBPF blocking maps
                #[cfg(target_os = "linux")]
                if let Some(ref enf_arc) = enf_opt {
                    if let Ok(mut guard) = enf_arc.lock() {
                        if let Some(ref mut enf) = *guard {
                            if let Err(e) = enf.load_rules(fast_path.rules()) {
                                tracing::warn!("Enforcer reload failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}
