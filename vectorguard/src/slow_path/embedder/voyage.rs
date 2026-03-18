use anyhow::{Context, Result};
use async_trait::async_trait;

use super::EmbedProvider;

/// Voyage AI embedding dimensions by model:
/// voyage-3:       1024
/// voyage-3-lite:  512
/// voyage-code-3:  1024
const VOYAGE_DEFAULT_DIM: usize = 1024;

pub struct VoyageEmbedder {
    model:   String,
    api_key: Option<String>,
    client:  reqwest::Client,
    dim:     usize,
}

impl VoyageEmbedder {
    pub fn new(model: String, api_key: Option<String>) -> Self {
        let dim = match model.as_str() {
            "voyage-3-lite" => 512,
            _ => VOYAGE_DEFAULT_DIM,
        };
        Self { model, api_key, client: reqwest::Client::new(), dim }
    }
}

#[async_trait]
impl EmbedProvider for VoyageEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let key = self.api_key.as_deref().context("Voyage API key not set")?;

        let resp: serde_json::Value = self
            .client
            .post("https://api.voyageai.com/v1/embeddings")
            .bearer_auth(key)
            .json(&serde_json::json!({
                "input": [text],
                "model": self.model,
            }))
            .send()
            .await
            .context("Voyage API request failed")?
            .json()
            .await
            .context("Voyage response parse failed")?;

        if let Some(detail) = resp.get("detail") {
            anyhow::bail!("Voyage API error: {}", detail);
        }

        let vec: Vec<f32> = resp["data"][0]["embedding"]
            .as_array()
            .context("Missing embedding array in Voyage response")?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if vec.is_empty() {
            anyhow::bail!("Voyage returned empty embedding");
        }

        Ok(vec)
    }

    fn dim(&self) -> usize {
        self.dim
    }

    fn name(&self) -> &'static str {
        "voyage"
    }
}
