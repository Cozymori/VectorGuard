mod local;
mod openai;
mod voyage;
mod gemini;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tracing::warn;

use crate::config::{EmbedderBackend, EmbedderConfig};
use crate::event::{EventType, NormalizedEvent};

// ── Trait ─────────────────────────────────────────────────────

#[async_trait]
pub trait EmbedProvider: Send + Sync {
    async fn embed(&self, text: &str) -> Result<Vec<f32>>;
    fn dim(&self) -> usize;
    fn name(&self) -> &'static str;
}

// ── Public Embedder Wrapper ──────────────────────────────────

pub struct Embedder {
    provider: Box<dyn EmbedProvider>,
}

impl Embedder {
    pub fn new(cfg: EmbedderConfig) -> Self {
        let api_key = resolve_api_key(&cfg);

        let provider: Box<dyn EmbedProvider> = match cfg.backend {
            EmbedderBackend::Local => {
                if let Some(ref endpoint) = cfg.endpoint {
                    Box::new(local::OllamaEmbedder::new(
                        endpoint.clone(),
                        cfg.model.clone(),
                    ))
                } else {
                    Box::new(local::LocalEmbedder)
                }
            }
            EmbedderBackend::Openai => {
                Box::new(openai::OpenAiEmbedder::new(cfg.model.clone(), api_key))
            }
            EmbedderBackend::Voyage => {
                Box::new(voyage::VoyageEmbedder::new(cfg.model.clone(), api_key))
            }
            EmbedderBackend::Gemini => {
                Box::new(gemini::GeminiEmbedder::new(cfg.model.clone(), api_key))
            }
        };

        tracing::info!(
            "Embedder initialized: {} (dim={})",
            provider.name(),
            provider.dim()
        );

        Self { provider }
    }

    /// Returns the vector dimension for this backend
    pub fn dim(&self) -> usize {
        self.provider.dim()
    }

    /// Embed a NormalizedEvent → validated fixed-dimension vector
    pub async fn embed(&self, event: &NormalizedEvent) -> Result<Vec<f32>> {
        let text = event_to_text(event);
        let vec = self.provider.embed(&text).await?;

        // Dimension validation (guards against API returning wrong size)
        let expected = self.provider.dim();
        if vec.len() != expected {
            bail!(
                "{} returned {} dims, expected {}",
                self.provider.name(),
                vec.len(),
                expected
            );
        }

        Ok(vec)
    }
}

// ── Helpers ──────────────────────────────────────────────────

fn resolve_api_key(cfg: &EmbedderConfig) -> Option<String> {
    if cfg.api_key_env.is_empty() {
        return None;
    }
    match std::env::var(&cfg.api_key_env) {
        Ok(key) if !key.is_empty() => Some(key),
        Ok(_) => {
            warn!(
                "Environment variable {} is empty — {} backend may fail",
                cfg.api_key_env,
                format!("{:?}", cfg.backend)
            );
            None
        }
        Err(_) => {
            warn!(
                "Environment variable {} not set — {} backend may fail",
                cfg.api_key_env,
                format!("{:?}", cfg.backend)
            );
            None
        }
    }
}

/// Convert a NormalizedEvent to a rich text representation for external embedding APIs
fn event_to_text(event: &NormalizedEvent) -> String {
    let kind = match &event.event_type {
        EventType::Exec => "exec".to_string(),
        EventType::FileAccess { path, flags } => {
            let mode = [
                if flags.read { "r" } else { "" },
                if flags.write { "w" } else { "" },
                if flags.execute { "x" } else { "" },
            ]
            .concat();
            format!("file_access {} mode={}", path, mode)
        }
        EventType::Network {
            direction,
            remote_ip,
            port,
            proto,
        } => format!(
            "net_{:?} {:?} {}:{}", direction, proto, remote_ip, port
        ),
        EventType::Privilege {
            syscall,
            capability,
        } => {
            let cap = capability.as_deref().unwrap_or("none");
            format!("privilege {} cap={}", syscall, cap)
        }
        EventType::Signal { signum, target_pid } => {
            format!("signal {} target_pid={}", signum, target_pid)
        }
    };

    let args_str = if event.process.args.is_empty() {
        String::new()
    } else {
        format!(" args=[{}]", event.process.args.join(", "))
    };

    let parent_str = if let Some(ref p) = event.parent {
        format!(" parent={}(pid={})", p.binary, p.pid)
    } else {
        String::new()
    };

    let cwd_str = if event.process.cwd.is_empty() {
        String::new()
    } else {
        format!(" cwd={}", event.process.cwd)
    };

    format!(
        "{} uid={} proc={}{}{}{} severity={:?}",
        kind,
        event.process.uid,
        event.process.binary,
        args_str,
        cwd_str,
        parent_str,
        event.severity,
    )
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;

    fn make_event(event_type: EventType, uid: u32, binary: &str) -> NormalizedEvent {
        NormalizedEvent {
            id: 0,
            timestamp: 0,
            source: EventSource::NativeEbpf,
            process: ProcessInfo {
                pid: 1, ppid: 0, uid, gid: 0,
                binary: binary.to_string(),
                args: vec!["--flag".into(), "value".into()],
                cwd: "/home/user".into(),
            },
            parent: Some(ProcessInfo {
                pid: 0, ppid: 0, uid: 0, gid: 0,
                binary: "systemd".to_string(),
                args: vec![], cwd: String::new(),
            }),
            event_type,
            severity: Severity::Info,
            action: Action::Allowed,
            rule_name: None,
            k8s: None,
            raw: serde_json::Value::Null,
        }
    }

    #[test]
    fn event_to_text_includes_args_and_parent() {
        let ev = make_event(EventType::Exec, 1000, "bash");
        let text = event_to_text(&ev);
        assert!(text.contains("args=[--flag, value]"));
        assert!(text.contains("parent=systemd(pid=0)"));
        assert!(text.contains("cwd=/home/user"));
        assert!(text.contains("severity=Info"));
    }

    #[test]
    fn event_to_text_file_access_includes_mode() {
        let ev = make_event(
            EventType::FileAccess {
                path: "/etc/shadow".into(),
                flags: FileFlags { read: true, write: false, execute: false },
            },
            0,
            "cat",
        );
        let text = event_to_text(&ev);
        assert!(text.contains("file_access /etc/shadow mode=r"));
    }

    #[test]
    fn local_embedder_dim() {
        let emb = local::LocalEmbedder;
        assert_eq!(emb.dim(), 64);
    }

    #[tokio::test]
    async fn local_embedder_returns_correct_dim() {
        let emb = local::LocalEmbedder;
        let vec = emb.embed("test event").await.unwrap();
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn local_embed_is_unit_normalized() {
        let ev = make_event(EventType::Exec, 1000, "nginx");
        let text = event_to_text(&ev);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let v = rt.block_on(local::LocalEmbedder.embed(&text)).unwrap();
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "norm = {}", norm);
    }

    #[test]
    fn different_texts_produce_different_vectors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let v1 = rt.block_on(local::LocalEmbedder.embed("exec uid=0 proc=bash")).unwrap();
        let v2 = rt.block_on(local::LocalEmbedder.embed("file_access /etc/shadow uid=0 proc=cat")).unwrap();
        assert_ne!(v1, v2);
    }
}
