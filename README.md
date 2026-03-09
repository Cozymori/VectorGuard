# VectorGuard

**Linux runtime security daemon** powered by eBPF and vector-based behavioral anomaly detection.

VectorGuard monitors system calls in real time, evaluates events against a fast TOML rule engine, and detects novel attack patterns using a per-process behavioral fingerprint stored in a vector database. When a threat is confirmed it enforces policy **in-kernel** with zero userspace round-trip — via eBPF blocking maps, `bpf_send_signal(SIGKILL)`, and LSM hooks returning `-EPERM`.

---

## Features

| Category | Capability |
|---|---|
| **Monitoring** | `execve`, `openat`, `connect` tracepoints + LSM hooks (`bprm_check_security`, `file_open`) |
| **Fast Path** | TOML rule engine — block / alert / log / allow by process name, path, port, UID |
| **Slow Path** | Per-PID behavioral context window; vector embedding + Qdrant cosine similarity search |
| **Enforcement** | In-kernel blocking via eBPF HashMaps, `bpf_send_signal(9)`, LSM `-EPERM` |
| **Adapters** | Native eBPF · Tetragon gRPC · Falco JSON · auditd text log |
| **K8s** | Namespace include/exclude filtering · label selector filtering · DaemonSet manifests |
| **Hot Reload** | File-watch driven config reload; pipeline + eBPF maps updated in ≤500 ms |
| **TUI** | Real-time ratatui dashboard (event stream, stats, config viewer); headless fallback |
| **Deploy** | Docker image · Helm chart · bare-metal `install.sh` |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Event Sources                                               │
│  ┌─────────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐  │
│  │ Native eBPF │  │ Tetragon │  │ Falco  │  │  auditd   │  │
│  │ tracepoint  │  │  gRPC    │  │  JSON  │  │  textlog  │  │
│  │ + LSM hook  │  │ stream   │  │  tail  │  │  tail     │  │
│  └──────┬──────┘  └────┬─────┘  └───┬────┘  └─────┬─────┘  │
│         └──────────────┴────────────┴──────────────┘        │
│                          NormalizedEvent                     │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
             ┌─────────────────────────────┐
             │  Scope Filter               │  binary glob · namespace · labels
             └──────────────┬──────────────┘
                            ▼
             ┌─────────────────────────────┐
             │  Fast Path  (sync, μs)      │  TOML rules → Block / Alert / Log
             └──────────────┬──────────────┘
                            ▼
             ┌─────────────────────────────┐
             │  Slow Path  (async, ms)     │  embed → context blend → Qdrant
             └──────────────┬──────────────┘
                            ▼
             ┌─────────────────────────────┐
             │  TUI / headless logger      │  ratatui or log-only in Docker
             └─────────────────────────────┘

Kernel-level enforcement (Linux ≥5.7):
  eBPF HashMaps ← Enforcer ← Fast Path block rules
  tracepoint: bpf_send_signal(SIGKILL)   LSM hook: return -EPERM
```

---

## Requirements

- **Linux kernel ≥ 5.7** (for eBPF ring buffer)
- **`CONFIG_BPF_LSM=y`** (optional — for proactive LSM enforcement)
- **Root / `CAP_SYS_ADMIN`** (to load eBPF programs)
- **Rust nightly** (for eBPF `bpfel-unknown-none` target, `-Z build-std=core`)
- **`bpf-linker`** (`cargo install bpf-linker`)
- **Qdrant** (optional — for slow path anomaly detection)

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/Cozymori/VectorGuard.git
cd VectorGuard
docker compose up -d
```

Both VectorGuard and Qdrant start automatically. VectorGuard runs in headless mode (logs to stdout) since there is no TTY. Qdrant is available at `http://localhost:6333`.

### Bare-Metal (Linux)

```bash
# Automated install: detects distro, installs deps, builds, creates systemd service
curl -fsSL https://raw.githubusercontent.com/Cozymori/VectorGuard/master/install.sh | sudo bash

# View logs
journalctl -u vectorguard -f

# Edit config and auto-reload (hot reload enabled by default)
sudo $EDITOR /etc/vectorguard/config.toml
```

### Manual Build

```bash
# 1. Install nightly toolchain and bpf-linker
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# 2. Build the eBPF kernel program
cargo +nightly build -p vectorguard-ebpf \
  --target bpfel-unknown-none --release -Z build-std=core

# 3. Build the userspace daemon (embeds the eBPF binary via include_bytes!)
cargo build -p vectorguard --release

# 4. Run (requires root)
sudo ./target/release/vectorguard --config vectorguard/config.toml
```

### Kubernetes

```bash
# With Helm
bash deploy-k8s.sh --adapter native_ebpf

# With raw manifests
kubectl apply -f deploy/k8s/

# Custom options
bash deploy-k8s.sh \
  --adapter native_ebpf \
  --exclude-ns kube-system,monitoring \
  --include-ns production
```

---

## Configuration

The default config is at `vectorguard/config.toml` (dev) or `/etc/vectorguard/config.toml` (production).

```toml
[system]
log_level  = "info"     # debug | info | warn | error
hot_reload = true       # watch config file and reload without restart

[scope]
# Glob patterns matched against process binary name. Empty = monitor all processes.
targets = []
# Kubernetes namespace filtering (non-K8s events are unaffected)
include_namespaces = []                                       # [] = all namespaces
exclude_namespaces = ["kube-system", "kube-public"]          # takes precedence
label_selectors    = []                                       # ["env=production"]

[adapter]
# native_ebpf | tetragon | falco | auditd
backend = "native_ebpf"

[adapter.tetragon]
endpoint = "http://localhost:54321"

[adapter.falco]
log_path = "/var/log/falco/events.json"

[adapter.auditd]
log_path = "/var/log/audit/audit.log"

[fast_path]
enabled        = true
rules_path     = "/etc/vectorguard/rules"
default_action = "log"   # action when no rule matches: block | alert | log

[slow_path]
enabled              = true
time_window_secs     = 60      # per-PID behavioral context window
similarity_threshold = 0.85    # cosine similarity cutoff for anomaly

[slow_path.embedder]
backend     = "local"          # local | openai
model       = ""               # openai: "text-embedding-ada-002"
api_key_env = ""               # env var name for API key

[slow_path.vectordb]
backend    = "qdrant"
url        = "http://localhost:6333"
collection = "behaviors"

[tui]
refresh_rate_ms = 200
theme           = "dark"       # dark | light
```

---

## Fast Path Rules

Rules live in `rules/*.toml`. All conditions in a rule must match (AND logic). Rules are evaluated in file order; the first match wins.

```toml
# Block any process that reads /etc/shadow
[[rules]]
name              = "block-shadow-access"
action            = "block"
match_path_prefix = ["/etc/shadow", "/etc/gshadow"]

# Alert when a web server spawns a shell
[[rules]]
name            = "alert-webserver-shell"
action          = "alert"
match_process   = ["nginx", "apache2", "php-fpm"]
match_exec_path = ["/bin/sh", "/bin/bash"]

# Alert on reverse-shell ports
[[rules]]
name       = "alert-suspicious-port"
action     = "alert"
match_port = [4444, 1337, 31337, 9001]

# Block UID 0 running network tools
[[rules]]
name            = "alert-root-nettools"
action          = "alert"
match_uid       = 0
match_exec_path = ["/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc"]
```

### Rule Fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Unique identifier (used in logs) |
| `action` | `block`/`alert`/`log`/`allow` | Response when rule matches |
| `match_process` | `[string]` | Glob match on process comm name |
| `match_path_prefix` | `[string]` | File access path prefix |
| `match_exec_path` | `[string]` | Exec filename prefix |
| `match_port` | `[u16]` | TCP destination port |
| `match_uid` | `u32` | Process UID |

`block` rules are also installed into the eBPF kernel maps — the kernel enforces them without waking userspace.

---

## Adapters

### Native eBPF
Requires Linux. Attaches tracepoints directly and uses an eBPF ring buffer for zero-copy event delivery. Also attaches LSM hooks for proactive blocking if `CONFIG_BPF_LSM=y`.

```toml
[adapter]
backend = "native_ebpf"
```

### Tetragon
Connects to a running [Tetragon](https://tetragon.io/) agent via gRPC. Streams `ProcessExec`, `ProcessExit`, and `ProcessKprobe` events. Reconnects automatically with 5 s backoff.

```toml
[adapter]
backend = "tetragon"

[adapter.tetragon]
endpoint = "http://localhost:54321"
```

### Falco
Tails a Falco JSON output file.

```toml
[adapter]
backend = "falco"

[adapter.falco]
log_path = "/var/log/falco/events.json"
```

### Auditd
Parses auditd `SYSCALL` records from the audit log.

```toml
[adapter]
backend = "auditd"

[adapter.auditd]
log_path = "/var/log/audit/audit.log"
```

---

## Slow Path Anomaly Detection

The slow path builds a **behavioral fingerprint** for each PID:

1. **Embed** — Convert event to a 64-dim feature vector (event type, severity, UID, binary name, path/port bytes). Unit-normalized for cosine similarity.
2. **Context blend** — Blend with the PID's recent context vector (α=0.7 current + 0.3 history) to represent cumulative behavior, not just the latest event.
3. **Search** — Query Qdrant with the blended vector. If no similar pattern found (cosine similarity < threshold), escalate to `Action::Alerted` and raise severity.
4. **Store** — Upsert the blended vector as a new baseline for future comparisons.

This approach reduces false positives from isolated events that are consistent with a process's established behavior pattern.

---

## Kubernetes Deployment

The DaemonSet runs on every node with the following privileges (required for eBPF):

```yaml
securityContext:
  capabilities:
    add: [SYS_ADMIN, BPF, PERFMON, NET_ADMIN, SYS_PTRACE]
```

An init container mounts the BPF filesystem if not already present:

```yaml
initContainers:
  - name: mount-bpf
    command: ["sh", "-c", "mount | grep -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf"]
```

A liveness probe checks `/tmp/vectorguard.ready` (written after all components initialize).

### Namespace filtering example

```bash
# Deploy watching only the "production" namespace, excluding "monitoring"
bash deploy-k8s.sh \
  --adapter native_ebpf \
  --include-ns production \
  --exclude-ns monitoring,logging
```

---

## Uninstall

```bash
# Bare-metal
sudo bash uninstall.sh

# Docker
docker compose down -v

# Kubernetes
bash deploy-k8s.sh --uninstall
# or: helm uninstall vectorguard
```

---

## Development

```bash
# Run tests (works on macOS/Linux without eBPF)
cargo test

# Check without building eBPF
cargo check

# Watch logs in Docker
docker compose logs -f vectorguard

# Trigger hot reload (edit and save config)
$EDITOR vectorguard/config.toml
```

### Project structure

```
vectorguard/
├── vectorguard-common/     # Shared kernel/userspace types (no_std compatible)
├── vectorguard-ebpf/       # eBPF kernel program (nightly, bpfel-unknown-none)
├── vectorguard/            # Userspace daemon
│   ├── src/
│   │   ├── main.rs         # Startup, pipeline, hot-reload wiring
│   │   ├── collector.rs    # eBPF loader + ring buffer poller (Linux)
│   │   ├── enforcer.rs     # eBPF blocking map owner (Linux)
│   │   ├── adapter/        # Tetragon · Falco · auditd adapters
│   │   ├── fast_path/      # TOML rule engine
│   │   ├── slow_path/      # Embedder · context window · Qdrant client
│   │   ├── scope.rs        # Process / K8s namespace filtering
│   │   ├── hotreload.rs    # Config file watcher
│   │   └── tui/            # ratatui terminal UI
│   ├── build.rs            # Proto codegen + eBPF binary embedding
│   └── config.toml         # Development config
├── rules/                  # Fast path rule files
├── deploy/
│   ├── k8s/                # Raw Kubernetes manifests
│   └── helm/vectorguard/   # Helm chart
├── Dockerfile
├── docker-compose.yml
├── install.sh              # Bare-metal installer
├── uninstall.sh
└── deploy-k8s.sh
```

---

## License

MIT
