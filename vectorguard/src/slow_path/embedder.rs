use anyhow::{Context, Result};
use tracing::warn;

use crate::config::{EmbedderBackend, EmbedderConfig};
use crate::event::{EventType, NormalizedEvent, Severity};

/// Qdrant에 저장할 벡터 차원 수 (local: 64, OpenAI text-embedding-ada-002: 1536)
pub const VECTOR_DIM: usize = 64;

pub struct Embedder {
    backend: EmbedderBackend,
    model:   String,
    api_key: Option<String>,
    client:  reqwest::Client,
}

impl Embedder {
    pub fn new(cfg: EmbedderConfig) -> Self {
        let api_key = if cfg.api_key_env.is_empty() {
            None
        } else {
            std::env::var(&cfg.api_key_env).ok()
        };

        Self {
            backend: cfg.backend,
            model:   cfg.model,
            api_key,
            client:  reqwest::Client::new(),
        }
    }

    pub async fn embed(&self, event: &NormalizedEvent) -> Result<Vec<f32>> {
        match self.backend {
            EmbedderBackend::Local  => Ok(local_embed(event)),
            EmbedderBackend::Openai => self.openai_embed(event).await,
            EmbedderBackend::Claude => {
                // Anthropic은 전용 임베딩 API 미제공 → local 폴백
                warn!("Claude 임베딩 백엔드는 미지원 — local로 폴백");
                Ok(local_embed(event))
            }
        }
    }

    async fn openai_embed(&self, event: &NormalizedEvent) -> Result<Vec<f32>> {
        let key = self.api_key.as_deref().context("OPENAI_API_KEY 미설정")?;
        let text = event_to_text(event);

        let resp: serde_json::Value = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .bearer_auth(key)
            .json(&serde_json::json!({
                "input": text,
                "model": self.model,
            }))
            .send()
            .await?
            .json()
            .await?;

        let vec: Vec<f32> = resp["data"][0]["embedding"]
            .as_array()
            .context("임베딩 응답 파싱 실패")?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        Ok(vec)
    }
}

// ── 로컬 결정론적 임베더 ────────────────────────────────────────

/// 이벤트를 VECTOR_DIM 차원 특성 벡터로 변환 (학습 없음, 결정론적)
fn local_embed(event: &NormalizedEvent) -> Vec<f32> {
    let mut v = vec![0.0f32; VECTOR_DIM];

    // [0-4] 이벤트 종류 원핫
    match &event.event_type {
        EventType::Exec           => v[0] = 1.0,
        EventType::FileAccess { .. } => v[1] = 1.0,
        EventType::Network { .. }    => v[2] = 1.0,
        EventType::Privilege { .. }  => v[3] = 1.0,
        EventType::Signal { .. }     => v[4] = 1.0,
    }

    // [5] 심각도 정규화
    v[5] = match event.severity {
        Severity::Info     => 0.0,
        Severity::Low      => 0.25,
        Severity::Medium   => 0.5,
        Severity::High     => 0.75,
        Severity::Critical => 1.0,
    };

    // [6] UID (root=1.0, 그 외 정규화)
    v[6] = if event.process.uid == 0 { 1.0 } else { (event.process.uid as f32).min(65535.0) / 65535.0 };

    // [7-22] 프로세스명 바이트 → 정규화 (최대 16자)
    for (i, &b) in event.process.binary.as_bytes().iter().take(16).enumerate() {
        v[7 + i] = b as f32 / 255.0;
    }

    // [23-62] 이벤트 종류별 추가 특성
    match &event.event_type {
        EventType::FileAccess { path, flags } => {
            for (i, &b) in path.as_bytes().iter().take(38).enumerate() {
                v[23 + i] = b as f32 / 255.0;
            }
            v[61] = if flags.write   { 1.0 } else { 0.0 };
            v[62] = if flags.execute { 1.0 } else { 0.0 };
        }
        EventType::Network { port, .. } => {
            v[23] = *port as f32 / 65535.0;
        }
        EventType::Privilege { syscall, .. } => {
            for (i, &b) in syscall.as_bytes().iter().take(16).enumerate() {
                v[23 + i] = b as f32 / 255.0;
            }
        }
        EventType::Signal { signum, target_pid } => {
            v[23] = *signum as f32 / 64.0;
            v[24] = (*target_pid as f32).min(65535.0) / 65535.0;
        }
        EventType::Exec => {}
    }

    // 유클리드 정규화 → 코사인 유사도 사용 가능
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-9 {
        v.iter_mut().for_each(|x| *x /= norm);
    }

    v
}

fn event_to_text(event: &NormalizedEvent) -> String {
    let kind = match &event.event_type {
        EventType::Exec                        => "exec".to_string(),
        EventType::FileAccess { path, .. }     => format!("file_access {}", path),
        EventType::Network { port, .. }        => format!("net_connect port {}", port),
        EventType::Privilege { syscall, .. }   => format!("privilege {}", syscall),
        EventType::Signal { signum, .. }       => format!("signal {}", signum),
    };
    format!("{} uid={} proc={}", kind, event.process.uid, event.process.binary)
}
