use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, RwLock};
use tracing::info;

#[cfg(target_os = "linux")]
use vectorguard::{collector, enforcer};
use vectorguard::{
    adapter, ai_advisor, config, event, fast_path, hotreload,
    incident, scope, slow_path, tui,
};
use config::AdapterBackend;
use event::NormalizedEvent;

const READY_FILE: &str = "/tmp/vectorguard.ready";

const SYSTEM_CONFIG: &str = "/etc/vectorguard/config.toml";

fn parse_args() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            // `vectorguard tui` → use system config
            "tui" => {
                return SYSTEM_CONFIG.to_string();
            }
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    return args[i + 1].clone();
                }
            }
            s if s.starts_with("--config=") => {
                return s.trim_start_matches("--config=").to_string();
            }
            "--help" | "-h" => {
                eprintln!("Usage: vectorguard [tui | --config <path>]");
                eprintln!("  tui                  Launch TUI with system config ({})", SYSTEM_CONFIG);
                eprintln!("  --config, -c <path>  Path to config.toml");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    // Default: if system config exists use it, otherwise fall back to local
    if std::path::Path::new(SYSTEM_CONFIG).exists() {
        SYSTEM_CONFIG.to_string()
    } else {
        "config.toml".to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Write logs to stderr so they don't corrupt the TUI on stdout
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let config_path = parse_args();

    let cfg = config::Config::load(&config_path)
        .with_context(|| format!("Failed to load config: {}", config_path))?;
    info!("VectorGuard starting | adapter={:?} | config={}", cfg.adapter.backend, config_path);

    let cfg_arc = Arc::new(RwLock::new(cfg.clone()));

    // ── Config Reload Broadcast Channel ──────────────────────────
    let (reload_tx, reload_rx) = watch::channel(cfg.clone());
    let slow_reload_rx = reload_tx.subscribe();

    // ── Hot Reload ────────────────────────────────────────────────
    if cfg.system.hot_reload {
        let cfg_arc2 = Arc::clone(&cfg_arc);
        let config_path2 = config_path.clone();
        tokio::spawn(async move {
            if let Err(e) = hotreload::watch(&config_path2, cfg_arc2, reload_tx).await {
                tracing::error!("Hot reload error: {}", e);
            }
        });
    }

    // ── Shared Kernel Enforcer (Linux only) ───────────────────────
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
            let fast_path_cfg = cfg_snap.fast_path.clone();

            tokio::spawn(async move {
                match collector::load_ebpf() {
                    Ok(mut ebpf) => {
                        match enforcer::Enforcer::from_ebpf(&mut ebpf) {
                            Ok(mut enf) => {
                                let tmp_fp = fast_path::FastPath::new(&fast_path_cfg);
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
                    Err(e) => tracing::error!("eBPF load failed: {:#}", e),
                }
            });
            info!("Native eBPF collector started");
        }

        #[cfg(not(target_os = "linux"))]
        let _ = AdapterBackend::NativeEbpf;

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
    let scope_filter    = scope::ScopeFilter::new(&cfg.scope);
    let fast_path       = fast_path::FastPath::new(&cfg.fast_path);
    let slow_path       = slow_path::SlowPath::new(&cfg.slow_path).await;
    let incident_logger = Arc::new(incident::IncidentLogger::new(None));
    let ai_advisor      = ai_advisor::AiAdvisor::new(
        cfg.ai_advisor.clone(),
        cfg.fast_path.rules_path.clone(),
    );

    // ── Slow Path Worker Task ─────────────────────────────────────
    // The pipeline best-effort forwards events here via try_send. If the
    // worker is backlogged on Qdrant, events are dropped from anomaly
    // detection rather than back-pressuring the main pipeline.
    let (slow_tx, slow_rx) = mpsc::channel::<NormalizedEvent>(1024);
    tokio::spawn(run_slow_worker(
        slow_rx, slow_path, incident_logger.clone(), slow_reload_rx,
    ));

    // ── Event Processing Pipeline Task ────────────────────────────
    #[cfg(target_os = "linux")]
    tokio::spawn(run_pipeline(
        raw_rx, proc_tx, slow_tx, scope_filter, fast_path,
        incident_logger.clone(), ai_advisor, reload_rx, Some(enf_shared),
    ));

    #[cfg(not(target_os = "linux"))]
    tokio::spawn(run_pipeline(
        raw_rx, proc_tx, slow_tx, scope_filter, fast_path,
        incident_logger.clone(), ai_advisor, reload_rx, None,
    ));

    // ── Signal ready (for K8s liveness probe) ────────────────────
    if let Err(e) = std::fs::write(READY_FILE, "") {
        tracing::warn!("Could not write ready file {}: {}", READY_FILE, e);
    } else {
        info!("Ready ({})", READY_FILE);
    }

    // ── Run TUI ───────────────────────────────────────────────────
    let config_text = std::fs::read_to_string(&config_path).unwrap_or_default();
    let app = tui::App::new(config_text, config_path.clone());
    let result = tui::run(app, Some(proc_rx)).await;

    // Cleanup ready file on exit
    let _ = std::fs::remove_file(READY_FILE);

    result
}

/// Event processing pipeline with live hot-reload support.
///
/// Synchronous (fast) stages run inline: scope → fast_path → incident logging
/// → ai_advisor. Anomaly detection runs in a separate worker (see
/// `run_slow_worker`) and is fed best-effort via `slow_tx.try_send`.
async fn run_pipeline(
    raw_rx:               mpsc::Receiver<NormalizedEvent>,
    proc_tx:              mpsc::Sender<NormalizedEvent>,
    slow_tx:              mpsc::Sender<NormalizedEvent>,
    mut scope_filter:     scope::ScopeFilter,
    mut fast_path:        fast_path::FastPath,
    incident_logger:      Arc<incident::IncidentLogger>,
    mut ai_advisor:       ai_advisor::AiAdvisor,
    mut reload_rx:        watch::Receiver<config::Config>,
    #[cfg(target_os = "linux")]
    enf_opt: Option<Arc<Mutex<Option<enforcer::Enforcer>>>>,
    #[cfg(not(target_os = "linux"))]
    _enf_opt: Option<()>,
) {
    // Wrap in Option so we can park (pending) the arm when the source closes,
    // keeping the pipeline alive for hot-reload events even if eBPF failed.
    let mut raw_rx_opt: Option<mpsc::Receiver<NormalizedEvent>> = Some(raw_rx);
    let mut slow_drops: u64 = 0;

    loop {
        tokio::select! {
            ev = async {
                match raw_rx_opt.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match ev {
                    None => {
                        // Source exhausted (eBPF failed / adapter stopped).
                        // Park this arm and keep the pipeline alive for reload events.
                        tracing::warn!("Event source closed — running in degraded mode (no events)");
                        raw_rx_opt = None;
                        continue;
                    }
                    Some(mut ev) => {
                        if !scope_filter.allows(&ev) {
                            continue;
                        }

                        fast_path.evaluate(&mut ev);
                        incident_logger.record(&ev);
                        ai_advisor.analyze(&ev).await;

                        // Fork a copy to the slow path worker. try_send is
                        // non-blocking: when the worker is backlogged on
                        // Qdrant, drop the analysis instead of stalling.
                        if slow_tx.try_send(ev.clone()).is_err() {
                            slow_drops = slow_drops.saturating_add(1);
                            if slow_drops.is_power_of_two() {
                                tracing::warn!(
                                    "slow_path worker backlogged; dropped {} events so far",
                                    slow_drops
                                );
                            }
                        }

                        if proc_tx.send(ev).await.is_err() {
                            break;
                        }
                    }
                }
            }

            Ok(()) = reload_rx.changed() => {
                let new_cfg = reload_rx.borrow().clone();
                tracing::info!("Pipeline reloading with new config");

                scope_filter = scope::ScopeFilter::new(&new_cfg.scope);
                fast_path    = fast_path::FastPath::new(&new_cfg.fast_path);
                ai_advisor.update_config(new_cfg.ai_advisor.clone());

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

/// Slow path worker: runs anomaly detection on every event the main pipeline
/// forwards. Escalations produce a separate incident record (the original
/// event already left the pipeline with its fast-path decision).
async fn run_slow_worker(
    mut slow_rx:    mpsc::Receiver<NormalizedEvent>,
    mut slow_path:  slow_path::SlowPath,
    incident_logger: Arc<incident::IncidentLogger>,
    mut reload_rx:  watch::Receiver<config::Config>,
) {
    loop {
        tokio::select! {
            ev = slow_rx.recv() => {
                match ev {
                    None => break,
                    Some(mut ev) => {
                        let prior = ev.action.clone();
                        slow_path.analyze(&mut ev).await;
                        if ev.action != prior {
                            incident_logger.record(&ev);
                        }
                    }
                }
            }
            Ok(()) = reload_rx.changed() => {
                let new_cfg = reload_rx.borrow().clone();
                slow_path = slow_path::SlowPath::new(&new_cfg.slow_path).await;
            }
        }
    }
}
