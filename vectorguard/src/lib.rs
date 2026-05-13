//! VectorGuard library — modules shared between the daemon binary and
//! integration tests. The binary entry point lives in `main.rs`.

#[cfg(target_os = "linux")]
pub mod collector;
pub mod enforcer;
pub mod ai_advisor;
pub mod approval;
pub mod config;
pub mod event;
pub mod adapter;
pub mod fast_path;
pub mod hotreload;
pub mod incident;
pub mod scope;
pub mod slow_path;
pub mod tui;
