#[cfg(target_os = "linux")]
mod collector;
#[cfg(target_os = "linux")]
mod enforcer;
mod ai_advisor;
mod config;
mod event;
mod adapter;
mod fast_path;
mod hotreload;
mod incident;
mod scope;
mod slow_path;
mod tui;

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, RwLock};
use tracing::info;

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
    tracing_subscriber::fmt::init();

    let config_path = parse_args();

    let cfg = config::Config::load(&config_path)
        .with_context(|| format!("Failed to load config: {}", config_path))?;
    info!("VectorGuard starting | adapter={:?} | config={}", cfg.adapter.backend, config_path);

    let cfg_arc = Arc::new(RwLock::new(cfg.clone()));

    // ── Config Reload Broadcast Channel ──────────────────────────
    let (reload_tx, reload_rx) = watch::channel(cfg.clone());

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

    // ── Event Processing Pipeline Task ────────────────────────────
    #[cfg(target_os = "linux")]
    tokio::spawn(run_pipeline(
        raw_rx, proc_tx, scope_filter, fast_path, slow_path,
        incident_logger.clone(), ai_advisor, reload_rx, Some(enf_shared),
    ));

    #[cfg(not(target_os = "linux"))]
    tokio::spawn(run_pipeline(
        raw_rx, proc_tx, scope_filter, fast_path, slow_path,
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
async fn run_pipeline(
    raw_rx:               mpsc::Receiver<NormalizedEvent>,
    proc_tx:              mpsc::Sender<NormalizedEvent>,
    mut scope_filter:     scope::ScopeFilter,
    mut fast_path:        fast_path::FastPath,
    mut slow_path:        slow_path::SlowPath,
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
                        slow_path.analyze(&mut ev).await;
                        incident_logger.record(&ev);
                        ai_advisor.analyze(&ev).await;

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
                slow_path    = slow_path::SlowPath::new(&new_cfg.slow_path).await;
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
