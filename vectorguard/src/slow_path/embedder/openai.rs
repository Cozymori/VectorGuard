use anyhow::{Context, Result};
use async_trait::async_trait;

use super::EmbedProvider;

/// OpenAI text-embedding-3-small: 1536 dims (default)
/// OpenAI text-embedding-3-large: 3072 dims
/// OpenAI text-embedding-ada-002: 1536 dims
const OPENAI_DEFAULT_DIM: usize = 1536;

pub struct OpenAiEmbedder {
    model:   String,
    api_key: Option<String>,
    client:  reqwest::Client,
    dim:     usize,
}

impl OpenAiEmbedder {
    pub fn new(model: String, api_key: Option<String>) -> Self {
        let dim = match model.as_str() {
            "text-embedding-3-large" => 3072,
            _ => OPENAI_DEFAULT_DIM,
        };
        Self { model, api_key, client: reqwest::Client::new(), dim }
    }
}

#[async_trait]
impl EmbedProvider for OpenAiEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let key = self.api_key.as_deref().context("OpenAI API key not set")?;

        let resp: serde_json::Value = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .bearer_auth(key)
            .json(&serde_json::json!({
                "input": text,
                "model": self.model,
            }))
            .send()
            .await
            .context("OpenAI API request failed")?
            .json()
            .await
            .context("OpenAI response parse failed")?;

        // Check for API error
        if let Some(err) = resp.get("error") {
            anyhow::bail!("OpenAI API error: {}", err);
        }

        let vec: Vec<f32> = resp["data"][0]["embedding"]
            .as_array()
            .context("Missing embedding array in OpenAI response")?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if vec.is_empty() {
            anyhow::bail!("OpenAI returned empty embedding");
        }

        Ok(vec)
    }

    fn dim(&self) -> usize {
        self.dim
    }

    fn name(&self) -> &'static str {
        "openai"
    }
}
