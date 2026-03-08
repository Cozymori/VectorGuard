use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── 최상위 ────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub system:     SystemConfig,
    pub scope:      ScopeConfig,
    pub adapter:    AdapterConfig,
    pub fast_path:  FastPathConfig,
    pub slow_path:  SlowPathConfig,
    pub tui:        TuiConfig,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("config 파일 읽기 실패: {}", path.as_ref().display()))?;
        toml::from_str(&raw).context("config.toml 파싱 실패")
    }
}

// ── System ────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemConfig {
    pub log_level:  String,
    pub hot_reload: bool,
}

// ── Scope ─────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScopeConfig {
    pub targets:              Vec<String>,
    pub exclude_namespaces:   Vec<String>,
}

// ── Adapter ───────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdapterConfig {
    pub backend:   AdapterBackend,
    pub tetragon:  TetragonConfig,
    pub falco:     FalcoConfig,
    pub auditd:    AuditdConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterBackend {
    Tetragon,
    Falco,
    Auditd,
    NativeEbpf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TetragonConfig {
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FalcoConfig {
    pub log_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditdConfig {
    pub log_path: String,
}

// ── Fast Path ─────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FastPathConfig {
    pub enabled:        bool,
    pub rules_path:     String,
    pub default_action: DefaultAction,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Block,
    Alert,
    Log,
}

// ── Slow Path ─────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlowPathConfig {
    pub enabled:              bool,
    pub time_window_secs:     u64,
    pub similarity_threshold: f32,
    pub embedder:             EmbedderConfig,
    pub vectordb:             VectorDbConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmbedderConfig {
    pub backend:     EmbedderBackend,
    pub model:       String,
    pub api_key_env: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EmbedderBackend {
    Local,
    Openai,
    Claude,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VectorDbConfig {
    pub backend:    VectorDbBackend,
    pub url:        String,
    pub collection: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VectorDbBackend {
    Qdrant,
    Usearch,
}

// ── TUI ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TuiConfig {
    pub refresh_rate_ms: u64,
    pub theme:           Theme,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Dark,
    Light,
}

// ── 테스트 ────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config() {
        let cfg = Config::load("config.toml").expect("config.toml 로드 실패");
        assert_eq!(cfg.adapter.backend, AdapterBackend::Tetragon);
        assert_eq!(cfg.slow_path.similarity_threshold, 0.85);
        assert!(cfg.system.hot_reload);
    }
}
