use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Top-Level ──────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub system:     SystemConfig,
    pub scope:      ScopeConfig,
    pub adapter:    AdapterConfig,
    pub fast_path:  FastPathConfig,
    pub slow_path:  SlowPathConfig,
    pub tui:        TuiConfig,
    #[serde(default)]
    pub ai_advisor: AiAdvisorConfig,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;
        toml::from_str(&raw).context("Failed to parse config.toml")
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
    /// Glob patterns matched against process binary name.
    /// Empty = monitor all processes.
    pub targets:              Vec<String>,
    /// K8s namespace glob patterns to include (K8s events only).
    /// Empty = include all namespaces.
    pub include_namespaces:   Vec<String>,
    /// K8s namespace glob patterns to exclude.
    /// Takes precedence over include_namespaces.
    pub exclude_namespaces:   Vec<String>,
    /// K8s label selectors: "key=value" pairs that must ALL match.
    /// Empty = no label filtering.
    pub label_selectors:      Vec<String>,
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
    #[serde(default)]
    pub api_key_env: String,
    /// Optional custom endpoint (e.g. Ollama: "http://localhost:11434")
    #[serde(default)]
    pub endpoint:    Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EmbedderBackend {
    Local,
    Openai,
    Voyage,
    Gemini,
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

// ── AI Advisor ────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AiAdvisorConfig {
    pub enabled:             bool,
    pub api_key:             String,
    pub trigger_threshold:   u32,
    pub cooldown_seconds:    u64,
    pub context_window_size: usize,
    pub window_secs:         u64,
}

impl Default for AiAdvisorConfig {
    fn default() -> Self {
        Self {
            enabled:             false,
            api_key:             String::new(),
            trigger_threshold:   3,
            cooldown_seconds:    300,
            context_window_size: 20,
            window_secs:         60,
        }
    }
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

// ── Tests ─────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config() {
        let cfg = Config::load("config.toml").expect("Failed to load config.toml");
        assert_eq!(cfg.adapter.backend, AdapterBackend::Tetragon);
        assert_eq!(cfg.slow_path.similarity_threshold, 0.85);
        assert!(cfg.system.hot_reload);
    }
}
