use anyhow::{Context, Result};
use async_trait::async_trait;

use super::EmbedProvider;

/// Google Gemini embedding dimensions:
/// text-embedding-004: 768
const GEMINI_DEFAULT_DIM: usize = 768;

pub struct GeminiEmbedder {
    model:   String,
    api_key: Option<String>,
    client:  reqwest::Client,
}

impl GeminiEmbedder {
    pub fn new(model: String, api_key: Option<String>) -> Self {
        Self {
            model,
            api_key,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl EmbedProvider for GeminiEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let key = self.api_key.as_deref().context("Gemini API key not set")?;

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:embedContent?key={}",
            self.model, key
        );

        let resp: serde_json::Value = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "content": {
                    "parts": [{ "text": text }]
                }
            }))
            .send()
            .await
            .context("Gemini API request failed")?
            .json()
            .await
            .context("Gemini response parse failed")?;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("Gemini API error: {}", err);
        }

        let vec: Vec<f32> = resp["embedding"]["values"]
            .as_array()
            .context("Missing embedding.values in Gemini response")?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if vec.is_empty() {
            anyhow::bail!("Gemini returned empty embedding");
        }

        Ok(vec)
    }

    fn dim(&self) -> usize {
        GEMINI_DEFAULT_DIM
    }

    fn name(&self) -> &'static str {
        "gemini"
    }
}
