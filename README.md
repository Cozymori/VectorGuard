# VectorGuard

eBPF-based runtime security daemon for Linux.

VectorGuard monitors syscalls in real time, evaluates them against a TOML rule engine, and detects unknown attack patterns through vector-database behavioral analysis. When a threat is confirmed, it blocks **at the kernel level** — no userspace round trip, just `bpf_send_signal(SIGKILL)`.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Fast Path Rules](#fast-path-rules)
- [Slow Path Anomaly Detection](#slow-path-anomaly-detection)
- [Adapters](#adapters)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Testing](#testing)
- [Project Layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [License](#license)

---

## Features

### Monitoring
- Tracepoints for `execve`, `openat`, and `connect`
- LSM hooks (`bprm_check_security`, `file_open`) — attached automatically when the kernel supports them

### Detection (Fast Path)
- TOML rule engine matching on process name, file path, port, and UID
- Four actions: `block`, `alert`, `log`, `allow`
- Hot reload — changes are picked up within 500 ms of saving a rule file

### Detection (Slow Path)
- Behavioral events are embedded as 64-dimensional vectors
- Per-PID context blending over a sliding time window (70% current event + 30% history)
- Cosine similarity search in Qdrant — events with no nearby neighbor are flagged as anomalous

### Enforcement
- Targets (process name / port / UID) are written to eBPF hash maps
- On match, the tracepoint sends `bpf_send_signal(9)` — **immediate SIGKILL**
- All kernel-side; no userspace round trip

### Adapters
Beyond native eBPF, VectorGuard ingests events from:
- **Tetragon** — gRPC streaming
- **Falco** — JSON log tailing
- **auditd** — `audit.log` parsing

### Other
- **Kubernetes** — namespace and label filtering, DaemonSet / Helm deployment
- **TUI** — ratatui dashboard with live event stream, statistics, and config viewer
- **Headless mode** — log-only operation for Docker / systemd environments without a TTY

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Event sources                                                │
│  ┌─────────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐   │
│  │ Native eBPF │  │ Tetragon │  │ Falco  │  │  auditd   │   │
│  │ tracepoint  │  │  gRPC    │  │  JSON  │  │  textlog  │   │
│  │ + LSM hook  │  │ stream   │  │  tail  │  │  tail     │   │
│  └──────┬──────┘  └────┬─────┘  └───┬────┘  └─────┬─────┘   │
│         └──────────────┴────────────┴──────────────┘         │
│                        NormalizedEvent                        │
└────────────────────────────┬─────────────────────────────────┘
                             ▼
           ┌─────────────────────────────┐
           │  Scope filter               │  process glob · namespace · label
           └──────────────┬──────────────┘
                          ▼
           ┌─────────────────────────────┐
           │  Fast Path  (sync, μs)      │  TOML rules → Block / Alert / Log
           └──────────────┬──────────────┘
                          ▼
           ┌─────────────────────────────┐
           │  Slow Path  (async, ms)     │  embed → blend → Qdrant search
           └──────────────┬──────────────┘
                          ▼
           ┌─────────────────────────────┐
           │  TUI / headless logger      │  ratatui dashboard or log-only
           └─────────────────────────────┘

Kernel-level enforcement (Linux ≥ 5.7):
  eBPF hash map ← Enforcer ← Fast Path block rules
  Tracepoint sends bpf_send_signal(SIGKILL)
```

---

## Requirements

| Component | Required | Optional |
|-----------|----------|----------|
| **OS** | Linux (kernel ≥ 5.7) | Ubuntu 22.04 LTS recommended |
| **Privileges** | root or `CAP_SYS_ADMIN` | — |
| **Rust** | nightly toolchain | — |
| **bpf-linker** | `cargo install bpf-linker` | — |
| **CONFIG_BPF_LSM** | — | `=y` enables LSM hooks |
| **Qdrant** | — | required only for Slow Path |

> macOS and Windows users can test through Docker Desktop — see [Testing](#testing).

---

## Quick Start

### Option 1: Docker Compose (easiest)

```bash
git clone https://github.com/Cozymori/VectorGuard.git
cd VectorGuard
docker compose up -d
```

Starts VectorGuard alongside Qdrant. VectorGuard runs in headless (log-only) mode.

```bash
# Tail logs
docker compose logs -f vectorguard

# Stop
docker compose down -v
```

### Option 2: Automated install (bare-metal Linux)

```bash
git clone https://github.com/Cozymori/VectorGuard.git
cd VectorGuard
sudo bash install.sh
```

The install script handles:
- System packages (clang, llvm, libelf-dev, protobuf-compiler, …)
- Rust nightly toolchain and bpf-linker
- Building the eBPF program and userspace daemon
- Generating `/etc/vectorguard/config.toml` and the default rule set
- Registering and starting the systemd service
- Starting a Qdrant container if Docker is available

```bash
# Service status
sudo systemctl status vectorguard

# Live logs
sudo journalctl -u vectorguard -f

# Edit config (hot-reloaded automatically)
sudo nano /etc/vectorguard/config.toml
```

### Option 3: Manual build

```bash
# 1. Install Rust nightly and bpf-linker
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# 2. Build the eBPF kernel program
cargo +nightly build -p vectorguard-ebpf \
  --target bpfel-unknown-none --release -Z build-std=core

# 3. Build the userspace daemon (embeds the eBPF binary via include_bytes!)
cargo build -p vectorguard --release

# 4. Run (root required)
sudo ./target/release/vectorguard --config vectorguard/config.toml
```

---

## Configuration

Config file locations:
- Development: `vectorguard/config.toml`
- Production: `/etc/vectorguard/config.toml`

With `hot_reload = true`, changes apply within 500 ms — no restart needed.

```toml
[system]
log_level  = "info"     # debug | info | warn | error
hot_reload = true       # reload on config change

[scope]
targets            = []   # process-name globs to monitor (empty = all)
include_namespaces = []   # K8s namespace filter (empty = all)
exclude_namespaces = []   # excluded namespaces (takes precedence)
label_selectors    = []   # K8s label selectors (e.g. ["env=production"])

[adapter]
backend = "native_ebpf"  # native_ebpf | tetragon | falco | auditd

[fast_path]
enabled        = true
rules_path     = "/etc/vectorguard/rules"   # rule-file directory
default_action = "log"                      # action when no rule matches

[slow_path]
enabled              = true
time_window_secs     = 60     # per-PID context window (seconds)
similarity_threshold = 0.85   # cosine similarity threshold; below = anomaly

[slow_path.embedder]
backend     = "local"    # local | openai
model       = ""         # for openai: "text-embedding-ada-002"
api_key_env = ""         # environment variable holding the API key

[slow_path.vectordb]
backend    = "qdrant"
url        = "http://localhost:6333"
collection = "behaviors"

[tui]
refresh_rate_ms = 200
theme           = "dark"   # dark | light
```

### Per-adapter settings

```toml
# Tetragon (gRPC)
[adapter.tetragon]
endpoint = "http://localhost:54321"

# Falco JSON output
[adapter.falco]
log_path = "/var/log/falco/events.json"

# auditd
[adapter.auditd]
log_path = "/var/log/audit/audit.log"
```

---

## Fast Path Rules

Place `.toml` files in the `rules/` directory. Saved files are picked up immediately via hot reload.

### Evaluation model
- Conditions within a rule are combined with **AND** (all must match)
- Rules are evaluated in file order — **the first matching rule wins**
- `block` rules are also pushed into the eBPF hash map for in-kernel enforcement

### Available conditions

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `name` | string | Rule name (shown in logs) | `"block-shadow"` |
| `action` | string | `block` / `alert` / `log` / `allow` | `"block"` |
| `match_process` | [string] | Process-name glob | `["nginx", "py*"]` |
| `match_path_prefix` | [string] | File-access path prefix | `["/etc/shadow"]` |
| `match_exec_path` | [string] | Executable path prefix | `["/bin/sh"]` |
| `match_port` | [u16] | TCP destination port | `[4444, 1337]` |
| `match_uid` | u32 | Process UID | `0` |

### Built-in rules (`rules/default.toml`)

```toml
# Block access to sensitive credential files
[[rules]]
name              = "block-shadow-access"
action            = "block"
match_path_prefix = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"]

# Detect shells spawned by web servers
[[rules]]
name            = "alert-webserver-shell"
action          = "alert"
match_process   = ["nginx", "apache2", "httpd", "php-fpm"]
match_exec_path = ["/bin/sh", "/bin/bash", "/bin/dash"]

# Alert on connections to common reverse-shell ports
[[rules]]
name       = "alert-suspicious-port"
action     = "alert"
match_port = [4444, 1337, 31337, 9001, 8888, 6666]

# Flag root using network tools
[[rules]]
name            = "alert-root-nettools"
action          = "alert"
match_uid       = 0
match_exec_path = ["/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc"]
```

### Adding custom rules

```toml
# /etc/vectorguard/rules/my-rules.toml

# Block outbound traffic from Python
[[rules]]
name          = "block-python-outbound"
action        = "block"
match_process = ["python3", "python"]
match_port    = [80, 443, 8080]

# Watch SSH-key access from a specific UID
[[rules]]
name              = "alert-ssh-key-access"
action            = "alert"
match_path_prefix = ["/root/.ssh/", "/home/"]
match_uid         = 1000
```

---

## Slow Path Anomaly Detection

The Slow Path catches **unknown attack patterns** that no rule covers.

### How it works

```
event arrives
    │
    ▼
1. Embed — convert the event into a 64-dim vector
   (event type, severity, UID, binary name, path/port, …)
    │
    ▼
2. Blend — mix with recent behavior for the same PID
   (70% current event + 30% history)
    │
    ▼
3. Search — cosine similarity in Qdrant
   neighbor found (≥ 0.85) → benign
   no neighbor   (< 0.85) → anomaly → escalate to Alert
    │
    ▼
4. Store — upsert the blended vector into Qdrant for future comparisons
```

### Setting up Qdrant

```bash
# Run Qdrant in Docker
docker run -d --name qdrant -p 6333:6333 \
  -v qdrant_data:/qdrant/storage \
  qdrant/qdrant:v1.9.0

# Health check
curl http://localhost:6333/healthz
```

To disable Slow Path:
```toml
[slow_path]
enabled = false
```

---

## Adapters

VectorGuard supports multiple event sources, selected via `[adapter]`.

### Native eBPF (default)

Attaches tracepoints directly and consumes events from an eBPF ring buffer.
LSM hooks are added automatically when the kernel ships with `CONFIG_BPF_LSM=y`.

```toml
[adapter]
backend = "native_ebpf"
```

### Tetragon

Connects to a [Tetragon](https://tetragon.io/) agent over gRPC and streams `ProcessExec`, `ProcessExit`, and `ProcessKprobe` events. Reconnects automatically every 5 seconds on disconnect.

```toml
[adapter]
backend = "tetragon"

[adapter.tetragon]
endpoint = "http://localhost:54321"
```

### Falco

Tails Falco's JSON output.

```toml
[adapter]
backend = "falco"

[adapter.falco]
log_path = "/var/log/falco/events.json"
```

### auditd

Parses `SYSCALL` records from auditd.

```toml
[adapter]
backend = "auditd"

[adapter.auditd]
log_path = "/var/log/audit/audit.log"
```

---

## Kubernetes Deployment

Deploy as a DaemonSet on every node.

### Deploying

```bash
# Helm chart
bash deploy-k8s.sh --adapter native_ebpf

# With namespace filtering
bash deploy-k8s.sh \
  --adapter native_ebpf \
  --include-ns production \
  --exclude-ns kube-system,monitoring

# Raw manifests
kubectl apply -f deploy/k8s/
```

### Required capabilities

The DaemonSet needs the following to load eBPF:

```yaml
securityContext:
  capabilities:
    add: [SYS_ADMIN, BPF, PERFMON, NET_ADMIN, SYS_PTRACE]
```

An init container mounts the BPF filesystem, and `/tmp/vectorguard.ready` is used as the liveness probe.

---

## Testing

### Docker E2E tests (macOS / Windows / Linux)

All you need is Docker Desktop — no native Linux environment required.

```bash
# Build the test image (compiles eBPF + daemon inside the container)
docker build -f Dockerfile.test -t vectorguard-test .

# Run the E2E suite
docker run --rm --privileged --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  vectorguard-test
```

#### Test sections (17 checks)

| # | Section | Checks |
|---|---------|--------|
| 0 | Environment | BPF filesystem, tracepoints, BTF, LSM |
| 1 | Binary | binary, config, and rule files present |
| 2 | Startup | daemon boots, ready file, log messages, LSM hooks, no eBPF errors |
| 3 | Shadow | `/etc/shadow` access event captured |
| 4 | Port | connection to suspicious ports (4444, 1337) detected |
| 5 | Hot reload | config change applied without restart |
| 6 | Dynamic rule | adding a rule + reload blocks `nc` |
| 7 | Liveness | daemon still alive after the full run |

#### Interactive shell

```bash
docker run --rm -it --privileged --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  --entrypoint bash vectorguard-test
```

### Unit tests

```bash
# Runs on macOS or Linux (no eBPF needed)
cargo test
```

### Full Ubuntu test suite

See [TESTING.md](TESTING.md) for the detailed Ubuntu guide.

---

## Project Layout

```
VectorGuard/
│
├── vectorguard-common/          # Shared types (no_std-compatible)
│   └── src/lib.rs               #   RawEvent, EventKind, EventPayload
│
├── vectorguard-ebpf/            # eBPF kernel program (nightly, bpfel-unknown-none)
│   ├── src/main.rs              #   tracepoint handlers + LSM hooks
│   └── .cargo/config.toml       #   BPF target / linker config
│
├── vectorguard/                 # Userspace daemon
│   ├── src/
│   │   ├── main.rs              #   entry point, pipeline wiring, hot reload
│   │   ├── collector.rs         #   eBPF loader + ring-buffer polling (Linux)
│   │   ├── enforcer.rs          #   eBPF block-map management (Linux)
│   │   ├── adapter/             #   Tetragon · Falco · auditd adapters
│   │   ├── fast_path/           #   TOML rule engine
│   │   │   └── rules.rs         #     parse · match · evaluate
│   │   ├── slow_path/           #   embedding · context window · Qdrant
│   │   ├── scope.rs             #   process / namespace filtering
│   │   ├── hotreload.rs         #   config-file watcher
│   │   └── tui/                 #   ratatui terminal UI
│   ├── build.rs                 #   proto codegen + eBPF binary embedding
│   └── config.toml              #   development defaults
│
├── rules/                       # Fast Path rule files (.toml)
│   └── default.toml             #   7 built-in security rules
│
├── deploy/
│   ├── k8s/                     #   Kubernetes raw manifests
│   └── helm/vectorguard/        #   Helm chart
│
├── Dockerfile                   # Production image
├── Dockerfile.test              # E2E test image
├── docker-compose.yml           # VectorGuard + Qdrant
├── test_e2e_docker.sh           # Docker E2E test runner
├── install.sh                   # Bare-metal installer
├── uninstall.sh                 # Uninstaller
├── deploy-k8s.sh                # Kubernetes deployer
└── TESTING.md                   # Ubuntu test guide
```

### Event flow

```
Kernel (eBPF)                       Userspace (daemon)
─────────────                       ────────────────────
sys_enter_execve ──┐
sys_enter_openat ──┤── ring buffer ──→ collector.rs
sys_enter_connect ─┘                      │
                                          ▼
BLOCKED_COMMS ◄──── enforcer.rs ◄── fast_path/rules.rs
BLOCKED_PORTS                             │
BLOCKED_UIDS                              ▼
                                    slow_path/ (Qdrant)
                                          │
                                          ▼
                                    tui/ (dashboard or log)
```

---

## Troubleshooting

### eBPF fails to load

```
ERROR eBPF load failed: ...
```

- Run as root: `sudo ./vectorguard ...`
- Ensure the BPF filesystem is mounted: `mount | grep bpf`
- If not: `sudo mount -t bpf bpf /sys/fs/bpf`

### LSM hook unavailable warning

```
WARN LSM hook 'bprm_check_security' unavailable
```

- This is non-fatal. Tracepoint-based enforcement still works.
- To enable LSM hooks: `cat /boot/config-$(uname -r) | grep BPF_LSM`
- `CONFIG_BPF_LSM=y` is required.

### Qdrant connection failed

```
WARN Slow Path: Qdrant connection failed
```

- Check Docker: `docker ps | grep qdrant`
- Check the port: `curl http://localhost:6333/healthz`
- To run without Qdrant, set `enabled = false` under `[slow_path]`.

### Process isn't blocked

1. Confirm the rule's `action` is `"block"` (`alert` / `log` do not block).
2. Make sure `match_process` matches the actual `comm`:
   ```bash
   cat /proc/<pid>/comm   # what the kernel sees
   ```
3. Set `log_level = "debug"` and check the logs for rule-match traces.

### No logs

- Set `log_level = "debug"` and wait for hot reload.
- systemd: `sudo journalctl -u vectorguard -n 50`
- Docker: `docker compose logs -f vectorguard`

### Docker E2E tests fail

- Make sure Docker Desktop is running.
- Confirm the `--privileged` flag is present.
- Check that Docker Desktop has enough CPU and memory allocated.

---

## Uninstall

```bash
# Bare-metal
sudo bash uninstall.sh

# Docker
docker compose down -v

# Kubernetes
bash deploy-k8s.sh --uninstall
# or
helm uninstall vectorguard
```

---

## License

MIT
