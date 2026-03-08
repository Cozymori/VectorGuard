mod auditd;
mod falco;
mod tetragon;

pub use auditd::AuditdAdapter;
pub use falco::FalcoAdapter;
pub use tetragon::TetragonAdapter;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::{AdapterBackend, Config};
use crate::event::{EventSource, NormalizedEvent};

#[async_trait]
pub trait Adapter: Send + Sync {
    async fn next_event(&mut self) -> Result<NormalizedEvent>;
    fn source(&self) -> EventSource;
}

/// Create an Adapter instance based on config
pub fn create(cfg: &Config) -> Box<dyn Adapter> {
    match cfg.adapter.backend {
        AdapterBackend::Tetragon   => Box::new(TetragonAdapter::new(&cfg.adapter.tetragon)),
        AdapterBackend::Falco      => Box::new(FalcoAdapter::new(&cfg.adapter.falco)),
        AdapterBackend::Auditd     => Box::new(AuditdAdapter::new(&cfg.adapter.auditd)),
        AdapterBackend::NativeEbpf => {
            // NativeEbpf uses collector.rs directly and should never reach here
            panic!("NativeEbpf is not created via adapter::create()")
        }
    }
}

/// Adapter event loop — forward events to mpsc channel
pub async fn run(mut adapter: Box<dyn Adapter>, tx: mpsc::Sender<NormalizedEvent>) {
    loop {
        match adapter.next_event().await {
            Ok(ev) => {
                if tx.send(ev).await.is_err() {
                    break; // receiver closed
                }
            }
            Err(e) => {
                warn!("{} adapter error: {}", adapter.source().name(), e);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }
}

impl EventSource {
    pub fn name(&self) -> &'static str {
        match self {
            EventSource::Tetragon   => "tetragon",
            EventSource::Falco      => "falco",
            EventSource::Auditd     => "auditd",
            EventSource::NativeEbpf => "native_ebpf",
        }
    }
}
