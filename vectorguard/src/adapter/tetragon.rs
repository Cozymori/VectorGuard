use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

use crate::config::TetragonConfig;
use crate::event::*;

use super::Adapter;

static EVENT_ID: AtomicU64 = AtomicU64::new(0);

/// Tetragon JSON HTTP adapter
/// Tetragon의 `/metrics` 또는 커스텀 JSON export 엔드포인트를 폴링
/// 실제 배포 시 gRPC streaming으로 교체 권장
pub struct TetragonAdapter {
    client:   reqwest::Client,
    endpoint: String,
}

impl TetragonAdapter {
    pub fn new(cfg: &TetragonConfig) -> Self {
        Self {
            client:   reqwest::Client::new(),
            endpoint: cfg.endpoint.clone(),
        }
    }
}

#[async_trait]
impl Adapter for TetragonAdapter {
    async fn next_event(&mut self) -> Result<NormalizedEvent> {
        // TODO: Tetragon gRPC streaming 구현
        // 현재는 health endpoint를 폴링해 alive 확인 후 placeholder 반환
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let health_url = format!("{}/healthz", self.endpoint);
        match self.client.get(&health_url).send().await {
            Ok(r) => debug!("Tetragon health: {}", r.status()),
            Err(e) => {
                return Err(anyhow::anyhow!("Tetragon 연결 실패: {}", e));
            }
        }

        anyhow::bail!("Tetragon gRPC adapter 미구현 — native_ebpf 또는 falco 사용 권장")
    }

    fn source(&self) -> EventSource {
        EventSource::Tetragon
    }
}

/// Tetragon JSON 이벤트 → NormalizedEvent 변환 (향후 gRPC 구현 시 사용)
#[allow(dead_code)]
fn parse_tetragon_json(v: &serde_json::Value) -> Option<NormalizedEvent> {
    let process_exec = v.get("process_exec")?;
    let process      = process_exec.get("process")?;

    let binary = process["binary"].as_str().unwrap_or("").to_string();
    let pid    = process["pid"].as_u64().unwrap_or(0) as u32;
    let uid    = process["uid"].as_u64().unwrap_or(0) as u32;

    Some(NormalizedEvent {
        id:         EVENT_ID.fetch_add(1, Ordering::Relaxed),
        timestamp:  0,
        source:     EventSource::Tetragon,
        process:    ProcessInfo {
            pid, ppid: 0, uid, gid: 0,
            binary,
            args: vec![],
            cwd:  String::new(),
        },
        parent:     None,
        event_type: EventType::Exec,
        severity:   Severity::Info,
        action:     Action::Allowed,
        k8s:        None,
        raw:        v.clone(),
    })
}
