mod context;
pub mod embedder;
mod vectordb;

use std::sync::Mutex;
use tracing::{debug, warn};

use crate::config::SlowPathConfig;
use crate::event::{Action, NormalizedEvent, Severity};
use context::ContextWindow;
use embedder::Embedder;
use vectordb::VectorDb;

pub struct SlowPath {
    embedder:  Embedder,
    vectordb:  VectorDb,
    threshold: f32,
    enabled:   bool,
    available: bool,
    /// Per-PID behavioral context window (interior mutability for &self access)
    context:   Mutex<ContextWindow>,
}

impl SlowPath {
    pub async fn new(cfg: &SlowPathConfig) -> Self {
        let embedder = Embedder::new(cfg.embedder.clone());
        let vectordb = VectorDb::new(&cfg.vectordb);
        let dim = embedder.dim();

        let available = if cfg.enabled {
            match vectordb.ensure_collection(dim).await {
                Ok(_) => {
                    tracing::info!("Slow Path initialized (Qdrant connected, dim={})", dim);
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
            context:   Mutex::new(ContextWindow::new(cfg.time_window_secs, dim)),
        }
    }

    /// Embed the event, blend with PID's behavioral context, then search Qdrant.
    /// If no similar behavior is found, escalate to Alerted.
    pub async fn analyze(&self, event: &mut NormalizedEvent) {
        if !self.enabled || !self.available {
            return;
        }

        // Already Blocked by Fast Path → no further analysis needed
        if event.action == Action::Blocked {
            return;
        }

        let current_vector = match self.embedder.embed(event).await {
            Ok(v)  => v,
            Err(e) => { warn!("Embedding failed: {}", e); return; }
        };

        // Blend current vector with this PID's recent behavioral history.
        // α=0.7 weighting: current event is authoritative, context adds signal.
        let search_vector = {
            let mut ctx = self.context.lock().unwrap();
            let blended = if let Some(ctx_vec) = ctx.context_vector(event.process.pid) {
                blend(&current_vector, &ctx_vec)
            } else {
                current_vector.clone()
            };
            // Push current event into context window *after* reading context
            // so the current event doesn't pollute its own search
            ctx.push(event.process.pid, event.timestamp, current_vector.clone());
            // Periodically clean up stale PIDs
            ctx.prune_stale_pids();
            blended
        };

        let scores = self.vectordb.search(search_vector.clone(), 5, self.threshold).await;

        let is_anomaly = match &scores {
            Ok(s)  => s.is_empty(),
            Err(e) => { warn!("Qdrant search failed: {}", e); false }
        };

        if is_anomaly && event.action == Action::Allowed {
            debug!(
                pid    = event.process.pid,
                binary = %event.process.binary,
                "slow_path: anomalous behavior detected → escalating to alert"
            );
            event.action = Action::Alerted;
            if event.severity < Severity::Medium {
                event.severity = Severity::Medium;
            }
        }

        // Store context-blended vector as baseline for future comparisons.
        // Using a deterministic hash of the binary name as the point ID keeps
        // the collection bounded by the number of distinct binaries on the
        // host: each upsert overwrites that binary's most recent baseline.
        let payload = serde_json::json!({
            "binary": event.process.binary,
            "ts":     event.timestamp,
        });
        let point_id = stable_id(&event.process.binary);
        let _ = self.vectordb.upsert(point_id, search_vector, payload).await;
    }
}

/// Deterministic 64-bit hash (FNV-1a) so Qdrant point IDs stay stable
/// across process restarts and overwrite cleanly.
fn stable_id(s: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut h = FNV_OFFSET_BASIS;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_norm(v: &[f32]) -> f32 {
        v.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    // ── stable_id ────────────────────────────────────────────

    #[test]
    fn stable_id_is_deterministic() {
        assert_eq!(stable_id("nginx"), stable_id("nginx"));
        assert_eq!(stable_id(""), stable_id(""));
    }

    #[test]
    fn stable_id_differs_across_inputs() {
        assert_ne!(stable_id("nginx"), stable_id("apache2"));
        assert_ne!(stable_id("sh"), stable_id("sH"));
    }

    #[test]
    fn stable_id_known_fnv1a_value() {
        // FNV-1a("") = 0xcbf29ce484222325 (offset basis itself)
        assert_eq!(stable_id(""), 0xcbf2_9ce4_8422_2325);
    }

    // ── blend ────────────────────────────────────────────────

    #[test]
    fn blend_returns_a_when_dims_mismatch() {
        let a = vec![1.0_f32, 0.0, 0.0];
        let b = vec![0.0_f32, 1.0];
        let out = blend(&a, &b);
        assert_eq!(out, a);
    }

    #[test]
    fn blend_output_is_unit_normalized() {
        let a = vec![1.0_f32, 0.0, 0.0, 0.0];
        let b = vec![0.0_f32, 1.0, 0.0, 0.0];
        let out = blend(&a, &b);
        let n = unit_norm(&out);
        assert!((n - 1.0).abs() < 1e-5, "norm = {}", n);
    }

    #[test]
    fn blend_weights_a_more_than_b() {
        // With alpha=0.7, a's component should outweigh b's.
        let a = vec![1.0_f32, 0.0, 0.0, 0.0];
        let b = vec![0.0_f32, 1.0, 0.0, 0.0];
        let out = blend(&a, &b);
        assert!(out[0] > out[1], "expected a-axis dominant: {:?}", out);
    }

    #[test]
    fn blend_zero_vectors_does_not_nan() {
        let a = vec![0.0_f32; 4];
        let b = vec![0.0_f32; 4];
        let out = blend(&a, &b);
        assert!(out.iter().all(|x| x.is_finite()));
    }
}

/// Linearly blend two unit vectors and re-normalize the result.
/// If dimensions mismatch, logs a warning and returns `a` unchanged.
fn blend(a: &[f32], b: &[f32]) -> Vec<f32> {
    if a.len() != b.len() {
        tracing::error!(
            "blend dimension mismatch: a={} b={} — using current vector only",
            a.len(),
            b.len()
        );
        return a.to_vec();
    }

    let alpha = 0.7f32;
    let beta = 1.0 - alpha;
    let mut result: Vec<f32> = a.iter().zip(b.iter()).map(|(x, y)| alpha * x + beta * y).collect();
    let norm: f32 = result.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-9 {
        result.iter_mut().for_each(|x| *x /= norm);
    }
    result
}
