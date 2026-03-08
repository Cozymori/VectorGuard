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
    available: bool,   // whether Qdrant connection is available
}

impl SlowPath {
    pub async fn new(cfg: &SlowPathConfig) -> Self {
        let embedder = Embedder::new(cfg.embedder.clone());
        let vectordb = VectorDb::new(&cfg.vectordb);

        let available = if cfg.enabled {
            match vectordb.ensure_collection(VECTOR_DIM).await {
                Ok(_) => {
                    tracing::info!("Slow Path initialized (Qdrant connected)");
                    true
                }
                Err(e) => {
                    warn!("Qdrant connection failed → slow path disabled: {}", e);
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

    /// Embed the event as a vector and search Qdrant for similar behaviors.
    /// If no similar behavior is found, treat as anomaly → escalate action/severity
    pub async fn analyze(&self, event: &mut NormalizedEvent) {
        if !self.enabled || !self.available {
            return;
        }

        // Already Blocked by Fast Path → no further analysis needed
        if event.action == Action::Blocked {
            return;
        }

        let vector = match self.embedder.embed(event).await {
            Ok(v)  => v,
            Err(e) => { warn!("Embedding failed: {}", e); return; }
        };

        let scores = self.vectordb.search(vector.clone(), 5, self.threshold).await;

        let is_anomaly = match &scores {
            Ok(s)  => s.is_empty(),  // no similar pattern found → anomaly
            Err(e) => { warn!("Qdrant search failed: {}", e); false }
        };

        if is_anomaly && event.action == Action::Allowed {
            debug!(
                binary = %event.process.binary,
                "slow_path: anomalous behavior detected → escalating to alert"
            );
            event.action = Action::Alerted;
            if event.severity < Severity::Medium {
                event.severity = Severity::Medium;
            }
        }

        // Store current event vector as baseline for future comparisons
        let payload = serde_json::json!({
            "pid":    event.process.pid,
            "binary": event.process.binary,
            "ts":     event.timestamp,
        });
        let _ = self.vectordb.upsert(event.id, vector, payload).await;
    }
}
