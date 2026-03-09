//! Per-PID time-windowed behavior context for Slow Path anomaly detection.
//!
//! The `ContextWindow` accumulates recent event vectors for each PID within a
//! configurable time window. When analyzing a new event, the Slow Path blends
//! the current vector with the PID's recent history to produce a richer
//! "behavioral context" vector — reducing false positives from one-off events.

use std::collections::{HashMap, VecDeque};

/// Maximum stored events per PID regardless of time window
const MAX_PER_PID: usize = 32;

pub struct ContextWindow {
    /// pid → ring of (timestamp_ns, normalized_vector)
    store:       HashMap<u32, VecDeque<(u64, Vec<f32>)>>,
    window_ns:   u64,  // time window in nanoseconds
    vector_dim:  usize,
}

impl ContextWindow {
    pub fn new(window_secs: u64, vector_dim: usize) -> Self {
        Self {
            store:      HashMap::new(),
            window_ns:  window_secs * 1_000_000_000,
            vector_dim,
        }
    }

    /// Push a new event vector into this PID's history, then prune stale entries.
    pub fn push(&mut self, pid: u32, timestamp_ns: u64, vector: Vec<f32>) {
        let ring = self.store.entry(pid).or_default();
        ring.push_back((timestamp_ns, vector));

        // Prune entries outside the time window
        let cutoff = timestamp_ns.saturating_sub(self.window_ns);
        while ring.front().map_or(false, |(ts, _)| *ts < cutoff) {
            ring.pop_front();
        }
        // Hard cap to prevent unbounded growth for long-lived PIDs
        while ring.len() > MAX_PER_PID {
            ring.pop_front();
        }
    }

    /// Return a recency-weighted average of past vectors for this PID, or `None`
    /// if the PID has no history yet (first event → no context available).
    pub fn context_vector(&self, pid: u32) -> Option<Vec<f32>> {
        let ring = self.store.get(&pid)?;
        if ring.is_empty() {
            return None;
        }

        let n = ring.len() as f32;
        let mut result = vec![0.0f32; self.vector_dim];
        let mut total_weight = 0.0f32;

        for (i, (_, vec)) in ring.iter().enumerate() {
            // Linear ramp: oldest entry gets weight 1/n, newest gets weight 1.0
            let weight = (i as f32 + 1.0) / n;
            for (r, v) in result.iter_mut().zip(vec.iter()) {
                *r += weight * v;
            }
            total_weight += weight;
        }

        if total_weight > 1e-9 {
            result.iter_mut().for_each(|x| *x /= total_weight);
        }

        // Re-normalize to unit vector for cosine similarity
        let norm: f32 = result.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-9 {
            result.iter_mut().for_each(|x| *x /= norm);
        }

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_event_returns_no_context() {
        let cw = ContextWindow::new(10, 4);
        assert!(cw.context_vector(1234).is_none());
    }

    #[test]
    fn context_vector_has_correct_dim() {
        let mut cw = ContextWindow::new(10, 4);
        cw.push(1, 0, vec![1.0, 0.0, 0.0, 0.0]);
        cw.push(1, 1_000_000_000, vec![0.0, 1.0, 0.0, 0.0]);
        let v = cw.context_vector(1).unwrap();
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn old_events_are_pruned() {
        let mut cw = ContextWindow::new(5, 4); // 5-second window
        let t0 = 0u64;
        let t1 = 10_000_000_000u64; // 10s later — t0 outside window
        cw.push(1, t0, vec![1.0, 0.0, 0.0, 0.0]);
        cw.push(1, t1, vec![0.0, 1.0, 0.0, 0.0]);
        // Only the second event should remain
        assert_eq!(cw.store[&1].len(), 1);
    }

    #[test]
    fn context_vector_is_unit_length() {
        let mut cw = ContextWindow::new(60, 4);
        cw.push(1, 0,             vec![1.0, 0.0, 0.0, 0.0]);
        cw.push(1, 1_000_000_000, vec![0.0, 1.0, 0.0, 0.0]);
        let v = cw.context_vector(1).unwrap();
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "norm = {}", norm);
    }
}
