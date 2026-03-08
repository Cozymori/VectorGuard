mod embedder;
mod vectordb;

pub use embedder::VECTOR_DIM;

use tracing::{debug, warn};

use crate::config::SlowPathConfig;
use crate::event::{Action, NormalizedEvent, Severity};
use embedder::Embedder;
use vectordb::VectorDb;

pub struct SlowPath {
    embedder:  Embedder,
    vectordb:  VectorDb,
    threshold: f32,
    enabled:   bool,
    available: bool,   // Qdrant 연결 가능 여부
}

impl SlowPath {
    pub async fn new(cfg: &SlowPathConfig) -> Self {
        let embedder = Embedder::new(cfg.embedder.clone());
        let vectordb = VectorDb::new(&cfg.vectordb);

        let available = if cfg.enabled {
            match vectordb.ensure_collection(VECTOR_DIM).await {
                Ok(_) => {
                    tracing::info!("Slow Path 초기화 완료 (Qdrant 연결됨)");
                    true
                }
                Err(e) => {
                    warn!("Qdrant 연결 실패 → slow path 비활성화: {}", e);
                    false
                }
            }
        } else {
            false
        };

        Self {
            embedder,
            vectordb,
            threshold: cfg.similarity_threshold,
            enabled:   cfg.enabled,
            available,
        }
    }

    /// 이벤트를 벡터로 변환 후 Qdrant에서 유사 행동 검색.
    /// 유사 행동이 없으면 anomaly → action/severity 상향
    pub async fn analyze(&self, event: &mut NormalizedEvent) {
        if !self.enabled || !self.available {
            return;
        }

        // Fast Path에서 이미 Blocked → 추가 분석 불필요
        if event.action == Action::Blocked {
            return;
        }

        let vector = match self.embedder.embed(event).await {
            Ok(v)  => v,
            Err(e) => { warn!("임베딩 실패: {}", e); return; }
        };

        let scores = self.vectordb.search(vector.clone(), 5, self.threshold).await;

        let is_anomaly = match &scores {
            Ok(s)  => s.is_empty(),  // 유사 패턴 없음 → anomaly
            Err(e) => { warn!("Qdrant 검색 실패: {}", e); false }
        };

        if is_anomaly && event.action == Action::Allowed {
            debug!(
                binary = %event.process.binary,
                "slow_path: 이상 행동 감지 → alert 상향"
            );
            event.action = Action::Alerted;
            if event.severity < Severity::Medium {
                event.severity = Severity::Medium;
            }
        }

        // 현재 이벤트 벡터 저장 (다음 이벤트 비교 기준)
        let payload = serde_json::json!({
            "pid":    event.process.pid,
            "binary": event.process.binary,
            "ts":     event.timestamp,
        });
        let _ = self.vectordb.upsert(event.id, vector, payload).await;
    }
}
