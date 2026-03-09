# VectorGuard — Work Report

**Repository:** https://github.com/Cozymori/VectorGuard  
**Language:** Rust (2024 edition)  
**Date:** 2026-03-09

---

## 1. Project Overview

VectorGuard is a Linux runtime security daemon that monitors host system calls and process behavior in real time, classifies events via a dual-path detection engine, and enforces security policy at the kernel level using eBPF. It is designed to operate in both bare-metal and Kubernetes environments and can ingest events from multiple sources: its own native eBPF probes, Tetragon (gRPC streaming), Falco (JSON logs), or auditd (text logs).

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Event Sources                                                      │
│  ┌─────────────┐  ┌──────────┐  ┌────────┐  ┌────────────────────┐ │
│  │ Native eBPF │  │ Tetragon │  │ Falco  │  │ auditd             │ │
│  │ (tracepoint │  │ (gRPC    │  │ (JSON  │  │ (text log tail)    │ │
│  │  + LSM hook)│  │ stream)  │  │ tail)  │  │                    │ │
│  └──────┬──────┘  └────┬─────┘  └───┬────┘  └────────┬───────────┘ │
│         └──────────────┴────────────┴─────────────────┘             │
│                               │ NormalizedEvent                     │
└───────────────────────────────┼─────────────────────────────────────┘
                                ▼
              ┌─────────────────────────────┐
              │  Scope Filter               │
              │  (glob match on binary name)│
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Fast Path (sync)           │
              │  TOML rule engine           │
              │  → Block / Alert / Log      │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Slow Path (async)          │
              │  Per-PID context window     │
              │  → Embed → Qdrant search    │
              │  → Anomaly detection        │
              └──────────────┬──────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  ratatui TUI                │
              │  (real-time event stream)   │
              └─────────────────────────────┘

Kernel-level enforcement (Linux only):
  eBPF blocking maps ← Enforcer ← FastPath block rules
  tracepoint: bpf_send_signal(SIGKILL)
  LSM hook:   return -EPERM
```

---

## 3. Crate Structure

| Crate | Role |
|---|---|
| `vectorguard-common` | Shared kernel/userspace types (`RawEvent`, `EventKind`, payloads). Compiles in both `no_std` (eBPF) and `std` (userspace) |
| `vectorguard-ebpf` | eBPF kernel program: tracepoints + LSM hooks + blocking maps |
| `vectorguard` | Main daemon: collector, enforcer, adapters, fast/slow path, TUI, hot reload |

---

## 4. Source Files

| File | Lines | Description |
|---|---|---|
| `vectorguard-common/src/lib.rs` | 91 | `RawEvent`, `EventKind`, `EventPayload` union, per-event payloads, `blocked` flag |
| `vectorguard-ebpf/src/main.rs` | 304 | eBPF tracepoints (execve/openat/connect), LSM hooks, 3 blocking HashMaps |
| `vectorguard/src/main.rs` | 187 | Startup orchestration, hot-reload wiring, shared enforcer, pipeline task |
| `vectorguard/src/config.rs` | 152 | Full config schema, TOML deserialization |
| `vectorguard/src/event/mod.rs` | 75 | `NormalizedEvent`, `EventType`, `Action`, `Severity`, `ProcessInfo` |
| `vectorguard/src/collector.rs` | 222 | eBPF loader, tracepoint/LSM attachment, ring buffer polling, event normalization |
| `vectorguard/src/enforcer.rs` | 135 | Userspace owner of eBPF blocking maps; `load_rules`, `block_comm/uid/port` |
| `vectorguard/src/scope.rs` | 90 | Glob-based process scope filter (3 unit tests) |
| `vectorguard/src/hotreload.rs` | 45 | `notify` watcher; broadcasts new config via `watch::Sender<Config>` |
| `vectorguard/src/fast_path/mod.rs` | 52 | `FastPath` struct; rule evaluation, exposes rules slice for Enforcer |
| `vectorguard/src/fast_path/rules.rs` | 364 | TOML rule DSL, `RuleSet`, `Rule`, `RuleAction`; 18 unit tests |
| `vectorguard/src/slow_path/context.rs` | 119 | `ContextWindow`: per-PID time-windowed vector ring; 4 unit tests |
| `vectorguard/src/slow_path/mod.rs` | 127 | `SlowPath`: embed → context blend → Qdrant search → anomaly escalation |
| `vectorguard/src/slow_path/embedder.rs` | 230 | Local 64-dim deterministic embedder + OpenAI backend; 6 unit tests |
| `vectorguard/src/slow_path/vectordb.rs` | 105 | Qdrant REST client: `ensure_collection`, `upsert`, `search` |
| `vectorguard/src/adapter/mod.rs` | — | Adapter factory + `run` loop |
| `vectorguard/src/adapter/tetragon.rs` | 276 | Tetragon gRPC streaming client (tonic); auto-reconnect with 5 s backoff |
| `vectorguard/src/adapter/falco.rs` | 155 | Async JSON log tail |
| `vectorguard/src/adapter/auditd.rs` | 156 | Async auditd SYSCALL record parser |
| `vectorguard/src/tui/mod.rs` | 65 | TUI entry point; `tokio::select!` on events + keyboard |
| `vectorguard/src/tui/app.rs` | 142 | `App` state model |
| `vectorguard/src/tui/render.rs` | 205 | ratatui layout and widget rendering |
| `vectorguard/build.rs` | — | Compiles Tetragon protobuf (tonic-build) + eBPF binary (aya-build, Linux only) |
| `rules/default.toml` | — | Default fast-path rules (block shadow access, alert webserver shell spawns, etc.) |

**Total:** ~3,400 lines of Rust

---

## 5. Implemented Features

### 5.1 eBPF Kernel Program

Three tracepoints monitor system calls:
- `sys_enter_execve` → `handle_exec`
- `sys_enter_openat` → `handle_file_open`
- `sys_enter_connect` → `handle_net_connect`

Each handler reads process metadata (PID, UID, comm), checks three eBPF blocking HashMaps, and if matched:
1. Calls `bpf_send_signal(9)` — SIGKILL delivered in-kernel with no userspace round-trip
2. Sets `RawEvent.blocked = 1` so userspace reflects the action accurately

Two LSM BPF programs provide proactive enforcement (requires `CONFIG_BPF_LSM=y`, kernel ≥ 5.7):
- `bprm_check_security` → `lsm_exec`: returns `-EPERM` before exec completes
- `file_open` → `lsm_file_open`: returns `-EPERM` before the file descriptor is created

LSM attachment is gracefully skipped with a warning if the kernel does not support it.

### 5.2 Kernel Enforcer (`enforcer.rs`)

The `Enforcer` struct takes ownership of the three eBPF blocking maps from the loaded `Ebpf` handle via `take_map()`. The kernel retains the maps via reference counting; the Enforcer holds the userspace file descriptors.

- `from_ebpf(ebpf)` — extracts `BLOCKED_COMMS`, `BLOCKED_PORTS`, `BLOCKED_UIDS`
- `load_rules(rules)` — clears maps and repopulates from all `action = Block` rules
- `block_comm(name)` / `block_uid(uid)` / `block_port(port)` — real-time map updates for slow-path anomalies
- Shared as `Arc<Mutex<Option<Enforcer>>>` between the collector task and `run_pipeline`

### 5.3 Fast Path Rule Engine (`fast_path/rules.rs`)

TOML-configurable rule DSL supporting:
- `match_process` — glob match on binary name (comm)
- `match_path_prefix` — file access path prefix
- `match_exec_path` — exec filename prefix
- `match_port` — destination TCP port list
- `match_uid` — specific UID

Actions: `block`, `alert`, `log`, `allow`. Builtin rules include block-shadow-access, alert-webserver-shell, block-ptrace. 18 unit tests.

### 5.4 Slow Path Anomaly Detection

**Embedder:** Converts a `NormalizedEvent` into a 64-dimensional feature vector using a deterministic local algorithm (event type one-hot, severity, UID, binary name bytes, path/port/syscall bytes). Unit-normalized for cosine similarity. OpenAI `text-embedding-ada-002` backend also available.

**Context Window (`slow_path/context.rs`):** Per-PID ring buffer of `(timestamp_ns, vector)` pairs within a configurable time window (`time_window_secs` in config). On each event:
1. Read PID's existing context vector (recency-weighted average)
2. Blend current vector with context at α=0.7 (current event is authoritative)
3. Push current vector into the ring (after search, not before)

This "behavioral fingerprint" reduces false positives from isolated anomalous-looking events that are actually consistent with the process's recent activity.

**VectorDB:** Qdrant REST API client. `search` with cosine similarity threshold; `upsert` stores context-blended vectors as baselines. If no similar pattern found → escalate to `Action::Alerted`, raise severity to at least `Medium`.

### 5.5 Multi-Source Adapters

| Adapter | Protocol | Notes |
|---|---|---|
| NativeEbpf | eBPF Ring Buffer | Linux only; zero-copy via `AsyncFd` |
| Tetragon | gRPC streaming | tonic client; processes `ProcessExec`, `ProcessExit`, `ProcessKprobe`; 5 s reconnect backoff |
| Falco | JSON log tail | async file tail with `tokio::fs` |
| Auditd | text log tail | SYSCALL record parser with nr→name mapping |

All adapters normalize to `NormalizedEvent` before the pipeline.

### 5.6 Hot Reload + Live Reconfiguration (C + D)

`hotreload.rs` watches `config.toml` with the `notify` crate (500 ms poll interval). On change:
1. Parses new config, writes to `Arc<RwLock<Config>>`
2. Sends new config via `tokio::sync::watch::Sender<Config>`

`run_pipeline` uses `tokio::select!` to interleave event processing with config-change notifications. On reload:
- `ScopeFilter` rebuilt from new `scope.targets`
- `FastPath` reloaded from new rules directory
- `SlowPath` reinitialized (new Qdrant collection / threshold / time window)
- Kernel enforcer's eBPF blocking maps repopulated from new block rules (D)

### 5.7 Scope Filter

Glob pattern matching on process binary name. Empty `targets` list = monitor everything. Filters events before they enter the pipeline to avoid wasting Fast/Slow Path resources on irrelevant processes.

### 5.8 TUI (ratatui)

Three-panel terminal UI:
- **Event stream** — scrolling list of normalized events with color-coded severity and action
- **Statistics** — event counts per type, blocked/alerted/allowed totals
- **Config** — live view of current `config.toml`

`tokio::select!` drives both keyboard input (`crossterm` event-stream) and the event channel.

---

## 6. Configuration Schema

```toml
[system]
log_level  = "info"
hot_reload = true

[scope]
targets             = []          # [] = monitor all processes
exclude_namespaces  = []

[adapter]
backend = "native_ebpf"           # native_ebpf | tetragon | falco | auditd

[adapter.tetragon]
endpoint = "http://localhost:54321"

[fast_path]
enabled        = true
rules_path     = "rules/"
default_action = "log"

[slow_path]
enabled              = true
time_window_secs     = 60         # context aggregation window per PID
similarity_threshold = 0.85

[slow_path.embedder]
backend     = "local"             # local | openai | claude
model       = "text-embedding-ada-002"
api_key_env = "OPENAI_API_KEY"

[slow_path.vectordb]
backend    = "qdrant"
url        = "http://localhost:6333"
collection = "vectorguard"
```

---

## 7. Build & Run

### Dependencies
- Rust toolchain (nightly for eBPF target)
- `protoc` (Protobuf compiler) — for Tetragon gRPC code generation
- Linux kernel ≥ 5.7 with `CONFIG_BPF_LSM=y` for LSM enforcement
- Qdrant (optional) — for slow path anomaly detection

### Build
```bash
# Non-Linux / dev check
cargo check -p vectorguard

# Linux full build (compiles eBPF + userspace)
cargo build --release -p vectorguard
```

### Run
```bash
# Requires root for eBPF program loading
sudo ./target/release/vectorguard

# With Qdrant for slow path
docker run -p 6333:6333 qdrant/qdrant
sudo ./target/release/vectorguard
```

---

## 8. Git History

| Commit | Description |
|---|---|
| `42e44a8` | feat: B/C/D — context aggregation, hot reload sync, eBPF map update |
| `2fc3d0b` | feat: kernel-level Enforcer with eBPF blocking maps and LSM hooks |
| `d1dbefb` | docs: initial work report |
| `2ddaa87` | feat: Tetragon gRPC streaming adapter |
| `bea98da` | feat: build.rs, scope filtering, and unit tests |
| `9f5f4e7` | chore: translate all Korean comments/strings to English |
| `a65983c` | feat: full pipeline (Fast Path / Slow Path / Adapter / TUI) |

---

## 9. Test Coverage

| Module | Tests |
|---|---|
| `fast_path/rules.rs` | 18 unit tests (rule matching, action precedence, builtin rules) |
| `slow_path/embedder.rs` | 6 unit tests (dimensions, normalization, cosine similarity, determinism) |
| `slow_path/context.rs` | 4 unit tests (first-event, dimension, pruning, unit-normalization) |
| `scope.rs` | 3 unit tests (empty targets, exact match, glob match) |

---

## 10. Security Design Notes

- **Kernel enforcement is proactive (LSM) and reactive (SIGKILL).** LSM hooks fire *before* the syscall completes; tracepoints fire concurrently and kill via signal. Combined, they cover cases where the kernel does not support BPF LSM.
- **Fail-open for LSM.** If `try_lsm_exec` or `try_lsm_file_open` returns an error, the program returns 0 (allow) rather than blocking legitimate system activity.
- **Zero userspace round-trip for known threats.** Once a comm/port/UID is in the eBPF blocking map, the kernel enforces it without waking userspace.
- **Context-aware anomaly detection.** The Slow Path does not judge events in isolation — it considers the PID's recent behavioral baseline, reducing noise from scripted processes.
- **Hot reload with immediate kernel effect.** Updating `rules/default.toml` and saving triggers a full pipeline rebuild + eBPF map repopulation within ≤500 ms.
