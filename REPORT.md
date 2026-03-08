# VectorGuard — Work Report

## Project Overview

**VectorGuard** is a Linux runtime security monitoring daemon written in Rust. It intercepts system calls via eBPF, evaluates events through a two-stage detection pipeline, and displays results in a terminal UI.

**Repository:** https://github.com/Cozymori/VectorGuard  
**Language:** Rust (Workspace: 3 crates)  
**Total source lines:** 2,916 (22 `.rs` files)  
**Test results:** 18 passed, 0 failed

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Event Sources                        │
│  ┌─────────────┐  ┌───────┐  ┌────────┐  ┌──────────┐ │
│  │ Native eBPF │  │ Falco │  │ Auditd │  │ Tetragon │ │
│  └──────┬──────┘  └───┬───┘  └───┬────┘  └────┬─────┘ │
└─────────┼─────────────┼──────────┼─────────────┼───────┘
          └─────────────┴──────────┴─────────────┘
                              │ mpsc channel (raw)
                              ▼
                    ┌─────────────────┐
                    │  Scope Filter   │  targets glob match
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Fast Path     │  TOML rule engine
                    │  (sync, <1ms)   │  block / alert / log
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Slow Path     │  vector embedding
                    │  (async)        │  + Qdrant similarity
                    └────────┬────────┘
                             │ mpsc channel (processed)
                    ┌────────▼────────┐
                    │   TUI (ratatui) │  Dashboard / Events / Config
                    └─────────────────┘
```

---

## Crate Structure

| Crate | Purpose |
|-------|---------|
| `vectorguard` | Main daemon — pipeline, TUI, adapters |
| `vectorguard-ebpf` | eBPF kernel program (no_std) |
| `vectorguard-common` | Shared types between kernel/userspace |

---

## Components Implemented

### 1. eBPF Kernel Program (`vectorguard-ebpf`)
- `execve` tracepoint → captures process execution
- `openat` tracepoint → captures file access with flags
- `connect` tracepoint → captures outbound network connections
- Ring buffer (1 MB) for kernel→userspace event transport

### 2. Event Pipeline (`vectorguard-common`, `event/mod.rs`)
- `RawEvent` — C-compatible struct shared between eBPF and userspace
- `NormalizedEvent` — rich userspace event type with:
  - `ProcessInfo` (pid, ppid, uid, gid, binary, args, cwd)
  - `EventType` enum (Exec, FileAccess, Network, Privilege, Signal)
  - `Severity` (Info → Critical), `Action` (Allowed/Blocked/Killed/Alerted)
  - `K8sMeta` (pod, namespace, container) for Kubernetes environments

### 3. Event Collectors

#### Native eBPF (`collector.rs`)
- Loads compiled eBPF object via `aya`
- Attaches tracepoints at runtime
- Async Ring Buffer polling → `NormalizedEvent`

#### Falco Adapter (`adapter/falco.rs`)
- Tails Falco JSON log file asynchronously
- Maps Falco priority (Emergency→Critical, Warning→Medium, etc.)
- Parses `execve`, `openat`, `connect` event types

#### Auditd Adapter (`adapter/auditd.rs`)
- Tails `/var/log/audit/audit.log`
- Parses SYSCALL records (key=value format)
- Maps syscall numbers to event types (x86_64)

#### Tetragon Adapter (`adapter/tetragon.rs`)
- Full gRPC streaming client via `tonic`
- Proto schema: `proto/tetragon.proto` (Tetragon API v1)
- Subscribes to `ProcessExec`, `ProcessExit`, `ProcessKprobe`
- Converts kprobe function names → FileAccess / Network / Privilege
- Populates `K8sMeta` from Pod information
- Auto-reconnect with 5s backoff on stream drop

### 4. Scope Filter (`scope.rs`)
- Filters events by `config.scope.targets`
- Glob pattern support (`nginx`, `py*`, etc.)
- Empty target list = monitor everything

### 5. Fast Path (`fast_path/`)
- Rule engine loading `.toml` rule files from `rules_path` directory
- Rule conditions (AND logic):
  - `match_process` — glob on binary name
  - `match_path_prefix` — file path prefix (FileAccess only)
  - `match_exec_path` — exec path prefix (Exec only)
  - `match_port` — destination port list (Network only)
  - `match_uid` — exact UID match
- Actions: `block`, `alert`, `log`, `allow`
- First-match-wins evaluation
- Falls back to built-in rules if no rule files found

**Built-in rules:**

| Rule | Trigger | Action |
|------|---------|--------|
| block-shadow-access | Access to `/etc/shadow`, `/etc/sudoers` | Block |
| alert-shell-exec-by-service | nginx/postgres spawning `/bin/sh` | Alert |
| alert-outbound-unusual-port | Ports 4444, 1337, 31337, etc. | Alert |
| alert-root-nettools | root running wget/curl/nc | Alert |

### 6. Slow Path (`slow_path/`)
- **Embedder** — converts events to 64-dim feature vectors:
  - Dimensions 0–4: event type one-hot encoding
  - Dimension 5: severity
  - Dimension 6: UID (root = 1.0)
  - Dimensions 7–22: process binary name bytes
  - Dimensions 23–62: event-specific features (path, port, syscall)
  - Unit-normalized (enables cosine similarity)
  - OpenAI `text-embedding-ada-002` backend also supported
- **VectorDb** — Qdrant REST API client:
  - Auto-creates collection on startup
  - Upserts event vectors after each evaluation
  - Cosine similarity search against past events
- **Anomaly detection**: no similar past events found → escalate to `Alerted`, raise severity to at least `Medium`
- Gracefully degrades if Qdrant is unavailable

### 7. TUI (`tui/`)
- Built with `ratatui` + `crossterm`
- Three tabs: **Dashboard**, **Events**, **Config**
- Dashboard: live stats cards (total / blocked / alerts / high-severity) + recent events table
- Events tab: scrollable full event list (↑↓ / j/k)
- Config tab: read-only `config.toml` viewer
- `tokio::select!` — simultaneous keyboard input and event stream handling
- Non-blocking key polling to avoid starving the event channel

### 8. Hot Reload (`hotreload.rs`)
- File watcher via `notify` crate
- Detects `config.toml` modifications
- Atomically updates `Arc<RwLock<Config>>` — zero downtime

### 9. Build System (`build.rs`)
- **Proto compilation**: `tonic-build` → generates Tetragon gRPC client (all platforms)
- **eBPF compilation**: `aya-build` cross-compiles for `bpfel-unknown-none` (Linux only, no-op on macOS)
- `OUT_DIR`-based artifact embedding for eBPF binary

---

## Configuration (`config.toml`)

```toml
[adapter]
backend = "tetragon"   # tetragon | falco | auditd | native_ebpf

[fast_path]
rules_path = "../rules"
default_action = "block"

[slow_path]
enabled = true
similarity_threshold = 0.85

[slow_path.embedder]
backend = "local"      # local | openai | claude

[slow_path.vectordb]
backend = "qdrant"
url = "http://localhost:6333"
```

---

## Test Coverage

| Module | Tests | What is tested |
|--------|-------|----------------|
| `fast_path::rules` | 8 | builtin rules, glob, uid, port, first-match-wins |
| `slow_path::embedder` | 6 | dimension, normalization, determinism, differentiation |
| `scope` | 3 | empty targets, exact match, glob match |
| `config` | 1 | load + field validation |
| **Total** | **18** | **18/18 pass** |

---

## Commit History

| Hash | Description |
|------|-------------|
| `a65983c` | Initial implementation — full pipeline, Fast/Slow path, adapters, TUI |
| `9f5f4e7` | Translate all Korean comments and strings to English |
| `bea98da` | build.rs, scope filtering, 18 unit tests |
| `2ddaa87` | Tetragon gRPC streaming adapter |

---

## File Map

```
vectorguard/
├── build.rs                        # Proto + eBPF build script
├── config.toml                     # Runtime configuration
├── proto/
│   └── tetragon.proto              # Tetragon API v1 schema
├── src/
│   ├── main.rs                     # Entry point + pipeline wiring
│   ├── config.rs                   # Config structs + loader
│   ├── event/mod.rs                # NormalizedEvent type definitions
│   ├── scope.rs                    # Process scope filter
│   ├── hotreload.rs                # config.toml file watcher
│   ├── collector.rs                # eBPF ring buffer collector (Linux)
│   ├── adapter/
│   │   ├── mod.rs                  # Adapter trait + factory + run loop
│   │   ├── tetragon.rs             # Tetragon gRPC streaming adapter
│   │   ├── falco.rs                # Falco JSON log tail adapter
│   │   └── auditd.rs               # Auditd SYSCALL log adapter
│   ├── fast_path/
│   │   ├── mod.rs                  # FastPath engine
│   │   └── rules.rs                # Rule types, loader, matcher + tests
│   ├── slow_path/
│   │   ├── mod.rs                  # SlowPath engine + anomaly detection
│   │   ├── embedder.rs             # Local / OpenAI embedder + tests
│   │   └── vectordb.rs             # Qdrant REST API client
│   └── tui/
│       ├── mod.rs                  # Terminal init + event-driven run loop
│       ├── app.rs                  # App state + push_event()
│       ├── event.rs                # Non-blocking keyboard handler
│       └── render.rs               # ratatui layout + widgets
vectorguard-ebpf/
└── src/main.rs                     # eBPF tracepoints (execve/openat/connect)
vectorguard-common/
└── src/lib.rs                      # RawEvent, EventKind, payloads (no_std)
rules/
└── default.toml                    # Default Fast Path rules
```

---

## Known Limitations / Future Work

| Item | Notes |
|------|-------|
| eBPF build requires Linux + nightly Rust | Expected — eBPF target constraint |
| Tetragon adapter requires `protoc` on build host | `brew install protobuf` on macOS |
| Scope filter not re-applied on hot reload | Requires pipeline restart |
| Slow path not re-initialized on hot reload | Qdrant collection persists across restarts |
| `exclude_namespaces` not implemented | K8s namespace filtering is a no-op |
| OpenAI embedder uses 1536 dims vs local 64 dims | Qdrant collection must be recreated when switching backends |
