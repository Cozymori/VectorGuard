use anyhow::Result;
use tracing::debug;

use crate::config::{VectorDbBackend, VectorDbConfig};

pub struct VectorDb {
    client:     reqwest::Client,
    base_url:   String,
    collection: String,
    backend:    VectorDbBackend,
}

impl VectorDb {
    pub fn new(cfg: &VectorDbConfig) -> Self {
        Self {
            client:     reqwest::Client::new(),
            base_url:   cfg.url.clone(),
            collection: cfg.collection.clone(),
            backend:    cfg.backend.clone(),
        }
    }

    /// Create collection if it does not exist
    pub async fn ensure_collection(&self, vector_size: usize) -> Result<()> {
        match self.backend {
            VectorDbBackend::Qdrant  => self.qdrant_ensure(vector_size).await,
            VectorDbBackend::Usearch => Ok(()), // uSearch is in-memory, no initialization needed
        }
    }

    /// Store a vector (upsert)
    pub async fn upsert(&self, id: u64, vector: Vec<f32>, payload: serde_json::Value) -> Result<()> {
        match self.backend {
            VectorDbBackend::Qdrant  => self.qdrant_upsert(id, vector, payload).await,
            VectorDbBackend::Usearch => Ok(()), // skip in-memory implementation
        }
    }

    /// Search for similar vectors → return list of cosine similarity scores
    pub async fn search(
        &self,
        vector: Vec<f32>,
        limit: usize,
        score_threshold: f32,
    ) -> Result<Vec<f32>> {
        match self.backend {
            VectorDbBackend::Qdrant  => self.qdrant_search(vector, limit, score_threshold).await,
            VectorDbBackend::Usearch => Ok(vec![]), // always unknown → treated as anomaly
        }
    }

    // ── Qdrant REST Implementation ────────────────────────────

    async fn qdrant_ensure(&self, vector_size: usize) -> Result<()> {
        let url = format!("{}/collections/{}", self.base_url, self.collection);
        let check = self.client.get(&url).send().await?;

        if check.status() == 404 {
            let body = serde_json::json!({
                "vectors": { "size": vector_size, "distance": "Cosine" }
            });
            self.client.put(&url).json(&body).send().await?;
            debug!("Qdrant collection created: {}", self.collection);
        }

        Ok(())
    }

    async fn qdrant_upsert(&self, id: u64, vector: Vec<f32>, payload: serde_json::Value) -> Result<()> {
        let url = format!("{}/collections/{}/points", self.base_url, self.collection);
        let body = serde_json::json!({
            "points": [{ "id": id, "vector": vector, "payload": payload }]
        });
        self.client.put(&url).json(&body).send().await?;
        Ok(())
    }

    async fn qdrant_search(
        &self,
        vector: Vec<f32>,
        limit: usize,
        score_threshold: f32,
    ) -> Result<Vec<f32>> {
        let url = format!("{}/collections/{}/points/search", self.base_url, self.collection);
        let body = serde_json::json!({
            "vector": vector,
            "limit": limit,
            "score_threshold": score_threshold,
        });

        let resp = self.client.post(&url).json(&body).send().await?;
        let data: serde_json::Value = resp.json().await?;

        let scores = data["result"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p["score"].as_f64().map(|s| s as f32))
                    .collect()
            })
            .unwrap_or_default();

        Ok(scores)
    }
}
