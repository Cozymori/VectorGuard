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
    info!("VectorGuard 시작 | adapter={:?}", cfg.adapter.backend);

    let cfg = Arc::new(RwLock::new(cfg));

    // ── 핫 리로드 ─────────────────────────────────────────────
    if cfg.read().await.system.hot_reload {
        let cfg_clone = Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(e) = hotreload::watch(CONFIG_PATH, cfg_clone).await {
                tracing::error!("핫 리로드 오류: {}", e);
            }
        });
    }

    // ── 이벤트 파이프라인 채널 ────────────────────────────────
    // raw_tx/rx : 수집기 → 처리 파이프라인
    // proc_tx/rx: 처리 파이프라인 → TUI
    let (raw_tx, raw_rx) = mpsc::channel::<NormalizedEvent>(4096);
    let (proc_tx, proc_rx) = mpsc::channel::<NormalizedEvent>(4096);

    // ── 이벤트 수집기 시작 ────────────────────────────────────
    {
        let cfg_snap = cfg.read().await.clone();

        #[cfg(target_os = "linux")]
        if cfg_snap.adapter.backend == AdapterBackend::NativeEbpf {
            let tx = raw_tx.clone();
            tokio::spawn(async move {
                match collector::load_ebpf() {
                    Ok(mut ebpf) => {
                        if let Err(e) = collector::run_collector(&mut ebpf, tx).await {
                            tracing::error!("eBPF 컬렉터 오류: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("eBPF 로드 실패: {}", e),
                }
            });
            info!("Native eBPF 컬렉터 시작");
        }

        #[cfg(not(target_os = "linux"))]
        let _ = AdapterBackend::NativeEbpf; // suppress unused warning

        if cfg_snap.adapter.backend != AdapterBackend::NativeEbpf {
            let adapter = adapter::create(&cfg_snap);
            let tx = raw_tx.clone();
            tokio::spawn(async move {
                adapter::run(adapter, tx).await;
            });
            info!("Adapter 시작: {:?}", cfg_snap.adapter.backend);
        }
    }
    drop(raw_tx); // spawn된 태스크들이 복사본을 들고 있음

    // ── Fast Path 초기화 ──────────────────────────────────────
    let fast_path = {
        let cfg_snap = cfg.read().await;
        fast_path::FastPath::new(&cfg_snap.fast_path)
    };

    // ── Slow Path 초기화 ──────────────────────────────────────
    let slow_path = {
        let cfg_snap = cfg.read().await;
        slow_path::SlowPath::new(&cfg_snap.slow_path).await
    };

    // ── 이벤트 처리 파이프라인 태스크 ────────────────────────
    tokio::spawn(run_pipeline(raw_rx, proc_tx, fast_path, slow_path));

    // ── TUI 실행 ──────────────────────────────────────────────
    let config_text = std::fs::read_to_string(CONFIG_PATH).unwrap_or_default();
    let app = tui::App::new(config_text);
    tui::run(app, Some(proc_rx)).await
}

/// 이벤트 처리 파이프라인: Fast Path → Slow Path → TUI 채널 전달
async fn run_pipeline(
    mut raw_rx:  mpsc::Receiver<NormalizedEvent>,
    proc_tx:     mpsc::Sender<NormalizedEvent>,
    fast_path:   fast_path::FastPath,
    slow_path:   slow_path::SlowPath,
) {
    while let Some(mut ev) = raw_rx.recv().await {
        // Phase 2: Fast Path (동기, 규칙 평가)
        fast_path.evaluate(&mut ev);

        // Phase 3: Slow Path (비동기, 벡터 유사도)
        slow_path.analyze(&mut ev).await;

        if proc_tx.send(ev).await.is_err() {
            break; // TUI 종료
        }
    }
}
