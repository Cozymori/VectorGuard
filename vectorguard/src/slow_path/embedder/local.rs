use anyhow::{Context, Result};
use async_trait::async_trait;

use super::EmbedProvider;

const LOCAL_DIM: usize = 64;

// ── Deterministic Local Embedder (no external API) ───────────

pub struct LocalEmbedder;

#[async_trait]
impl EmbedProvider for LocalEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        Ok(deterministic_embed(text))
    }

    fn dim(&self) -> usize {
        LOCAL_DIM
    }

    fn name(&self) -> &'static str {
        "local"
    }
}

/// Text → 64-dimensional deterministic vector using character-level hashing.
/// This is a lightweight fallback when no external embedding API is configured.
fn deterministic_embed(text: &str) -> Vec<f32> {
    let mut v = vec![0.0f32; LOCAL_DIM];

    for (i, byte) in text.bytes().enumerate() {
        let slot = i % LOCAL_DIM;
        // Mix position and byte value to spread features across dimensions
        v[slot] += (byte as f32) / 255.0;
        // Secondary slot for cross-dimension signal
        let slot2 = (byte as usize * 7 + i * 13) % LOCAL_DIM;
        v[slot2] += 0.3;
    }

    // Euclidean normalization → enables cosine similarity
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-9 {
        v.iter_mut().for_each(|x| *x /= norm);
    }

    v
}

// ── Ollama Local Embedder (local API) ────────────────────────

pub struct OllamaEmbedder {
    endpoint: String,
    model:    String,
    client:   reqwest::Client,
}

impl OllamaEmbedder {
    pub fn new(endpoint: String, model: String) -> Self {
        tracing::info!("Ollama embedder: endpoint={} model={}", endpoint, model);
        Self {
            endpoint,
            model,
            client: reqwest::Client::new(),
        }
    }

    /// Query Ollama to discover embedding dimension for the configured model
    #[allow(dead_code)]
    async fn discover_dim(&self) -> Option<usize> {
        let resp = self
            .client
            .post(format!("{}/api/embed", self.endpoint))
            .json(&serde_json::json!({
                "model": self.model,
                "input": "dim probe",
            }))
            .send()
            .await
            .ok()?;

        let data: serde_json::Value = resp.json().await.ok()?;
        data["embeddings"][0]
            .as_array()
            .map(|arr| arr.len())
    }
}

#[async_trait]
impl EmbedProvider for OllamaEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let resp = self
            .client
            .post(format!("{}/api/embed", self.endpoint))
            .json(&serde_json::json!({
                "model": self.model,
                "input": text,
            }))
            .send()
            .await
            .context("Ollama API request failed")?;

        let data: serde_json::Value = resp
            .json()
            .await
            .context("Ollama response parse failed")?;

        let vec: Vec<f32> = data["embeddings"][0]
            .as_array()
            .context("Missing embeddings array in Ollama response")?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if vec.is_empty() {
            anyhow::bail!("Ollama returned empty embedding");
        }

        Ok(vec)
    }

    fn dim(&self) -> usize {
        // Ollama model dimensions vary; default to 768 (nomic-embed-text)
        // The actual dimension is validated after embed() returns
        768
    }

    fn name(&self) -> &'static str {
        "ollama"
    }
}
