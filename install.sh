#!/usr/bin/env bash
# =============================================================================
# VectorGuard Installer — bare-metal Linux
# =============================================================================
# Supports: Ubuntu 20.04+, Debian 11+, RHEL/CentOS/Rocky 8+, Fedora 36+, Arch
# Requires: Linux kernel ≥5.7, root/sudo
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Cozymori/VectorGuard/master/install.sh | bash
#   -or-
#   ./install.sh [--no-qdrant] [--no-service] [--config /path/to/config.toml]
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/Cozymori/VectorGuard.git"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/vectorguard"
RULES_DIR="/etc/vectorguard/rules"
SERVICE_NAME="vectorguard"
QDRANT_VERSION="v1.9.0"
BUILD_DIR="$(mktemp -d /tmp/vectorguard-build-XXXXXX)"

OPT_NO_QDRANT=0
OPT_NO_SERVICE=0
OPT_CONFIG=""

# ── Color output ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}══ $* ══${RESET}"; }

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-qdrant)  OPT_NO_QDRANT=1 ;;
    --no-service) OPT_NO_SERVICE=1 ;;
    --config)     OPT_CONFIG="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [--no-qdrant] [--no-service] [--config FILE]"
      exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  die "This script must be run as root (use sudo)"
fi

# ── Kernel version check ──────────────────────────────────────────────────────
section "System checks"
KERNEL_VER=$(uname -r | cut -d. -f1-2 | tr -d '.')
if [[ $KERNEL_VER -lt 57 ]]; then
  die "Kernel $(uname -r) is too old. VectorGuard requires Linux ≥5.7 for eBPF LSM support."
fi
ok "Kernel $(uname -r) — OK"

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

DISTRO=$(detect_distro)
info "Detected distro: $DISTRO"

# ── Install system dependencies ───────────────────────────────────────────────
section "Installing system dependencies"

install_deps_debian() {
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    clang llvm libelf-dev pkg-config \
    protobuf-compiler \
    linux-headers-"$(uname -r)" \
    curl git ca-certificates \
    2>/dev/null || \
  apt-get install -y --no-install-recommends \
    clang llvm libelf-dev pkg-config \
    protobuf-compiler \
    linux-headers-generic \
    curl git ca-certificates
}

install_deps_rhel() {
  dnf install -y \
    clang llvm elfutils-libelf-devel pkgconfig \
    protobuf-compiler \
    kernel-headers \
    curl git ca-certificates 2>/dev/null || \
  yum install -y \
    clang llvm elfutils-libelf-devel pkgconfig \
    protobuf-compiler \
    kernel-headers \
    curl git ca-certificates
}

install_deps_arch() {
  pacman -Sy --noconfirm \
    clang llvm libelf \
    protobuf \
    linux-headers \
    curl git
}

case "$DISTRO" in
  ubuntu|debian|linuxmint|pop)  install_deps_debian ;;
  rhel|centos|rocky|almalinux|fedora) install_deps_rhel ;;
  arch|manjaro)                 install_deps_arch ;;
  *)
    warn "Unknown distro '$DISTRO'. Attempting Debian-style install..."
    install_deps_debian || die "Failed to install dependencies. Install manually: clang llvm libelf-dev protobuf-compiler"
    ;;
esac
ok "System dependencies installed"

# ── Rust toolchain ────────────────────────────────────────────────────────────
section "Rust toolchain"

if ! command -v rustup &>/dev/null; then
  info "Installing rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
  ok "rustup installed"
else
  source "$HOME/.cargo/env" 2>/dev/null || true
  ok "rustup already present ($(rustup --version 2>/dev/null | head -1))"
fi

rustup toolchain install stable 2>/dev/null | tail -1
rustup target add bpfel-unknown-none 2>/dev/null
rustup component add rust-src 2>/dev/null
ok "Rust targets and components ready"

# ── Clone / update source ─────────────────────────────────────────────────────
section "Fetching source"

# If running from inside the repo already, use that
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
  SOURCE_DIR="$SCRIPT_DIR"
  info "Using local source: $SOURCE_DIR"
else
  info "Cloning $REPO_URL..."
  git clone --depth=1 "$REPO_URL" "$BUILD_DIR/vectorguard"
  SOURCE_DIR="$BUILD_DIR/vectorguard"
  ok "Source cloned to $SOURCE_DIR"
fi

# ── Build ─────────────────────────────────────────────────────────────────────
section "Building VectorGuard"
info "This may take a few minutes..."

cd "$SOURCE_DIR"

# eBPF kernel program (no_std, BPF target)
cargo build -p vectorguard-ebpf \
  --target bpfel-unknown-none \
  --release \
  -Z build-std=core \
  2>&1 | grep -E "^error|Compiling vectorguard|Finished" || true

# Userspace daemon
cargo build -p vectorguard --release 2>&1 | grep -E "^error|Compiling vectorguard|Finished" || true

BINARY="$SOURCE_DIR/target/release/vectorguard"
[[ -f "$BINARY" ]] || die "Build failed: $BINARY not found"
ok "Build complete"

# ── Install binary ────────────────────────────────────────────────────────────
section "Installing binary"

install -Dm755 "$BINARY" "$INSTALL_DIR/vectorguard"
ok "Binary installed: $INSTALL_DIR/vectorguard"

# ── Install config & rules ────────────────────────────────────────────────────
section "Installing config"

mkdir -p "$CONFIG_DIR" "$RULES_DIR"

if [[ -n "$OPT_CONFIG" ]]; then
  install -Dm644 "$OPT_CONFIG" "$CONFIG_DIR/config.toml"
  info "Using custom config: $OPT_CONFIG"
elif [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
  # Write production-ready default config
  cat > "$CONFIG_DIR/config.toml" << 'TOML'
[system]
log_level  = "info"
hot_reload = true

[scope]
targets             = []
include_namespaces  = []
exclude_namespaces  = ["kube-system", "kube-public", "kube-node-lease"]
label_selectors     = []

[adapter]
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
default_action = "log"

[slow_path]
enabled              = false
time_window_secs     = 60
similarity_threshold = 0.85

[slow_path.embedder]
backend     = "local"
model       = ""
api_key_env = ""

[slow_path.vectordb]
backend    = "qdrant"
url        = "http://localhost:6333"
collection = "behaviors"

[tui]
refresh_rate_ms = 200
theme           = "dark"
TOML
  ok "Default config written: $CONFIG_DIR/config.toml"
else
  warn "Config already exists, skipping: $CONFIG_DIR/config.toml"
fi

# Install rules
cp -n "$SOURCE_DIR/rules/"*.toml "$RULES_DIR/" 2>/dev/null || true
ok "Rules installed: $RULES_DIR/"

# ── Qdrant (optional) ─────────────────────────────────────────────────────────
if [[ $OPT_NO_QDRANT -eq 0 ]]; then
  section "Qdrant vector database"

  if command -v docker &>/dev/null; then
    info "Starting Qdrant via Docker..."
    if docker ps --format '{{.Names}}' | grep -q "^qdrant$"; then
      ok "Qdrant container already running"
    else
      docker run -d \
        --name qdrant \
        --restart unless-stopped \
        -p 6333:6333 \
        -v qdrant_storage:/qdrant/storage \
        "qdrant/qdrant:$QDRANT_VERSION" \
        2>/dev/null && ok "Qdrant container started" \
        || warn "Qdrant start failed — slow path will be disabled until Qdrant is available"
    fi

    # Enable slow path in config
    sed -i 's/^enabled\s*=\s*false/enabled = true/' "$CONFIG_DIR/config.toml" 2>/dev/null || true

  else
    warn "Docker not found — skipping Qdrant install. Slow path anomaly detection will be disabled."
    warn "To enable later: install Docker and run:"
    warn "  docker run -d --name qdrant -p 6333:6333 qdrant/qdrant:$QDRANT_VERSION"
  fi
fi

# ── systemd service ───────────────────────────────────────────────────────────
if [[ $OPT_NO_SERVICE -eq 0 ]] && command -v systemctl &>/dev/null; then
  section "systemd service"

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SYSTEMD
[Unit]
Description=VectorGuard runtime security daemon
Documentation=https://github.com/Cozymori/VectorGuard
After=network.target
# Wait for Qdrant if it's managed by Docker
Wants=docker.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/vectorguard --config $CONFIG_DIR/config.toml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vectorguard

# eBPF requires elevated privileges
# CAP_SYS_ADMIN: load eBPF programs
# CAP_BPF:       eBPF syscall (kernel ≥5.8)
# CAP_PERFMON:   perf_event_open for tracepoints
# CAP_NET_ADMIN: network monitoring
# CAP_SYS_PTRACE: /proc access
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_PTRACE
NoNewPrivileges=false

# Mount BPF filesystem if not present
ExecStartPre=/bin/bash -c 'mount | grep -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'

[Install]
WantedBy=multi-user.target
SYSTEMD

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service $SERVICE_NAME is running"
  else
    warn "Service failed to start. Check logs: journalctl -u $SERVICE_NAME -n 50"
  fi
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
[[ -d "$BUILD_DIR" ]] && rm -rf "$BUILD_DIR"

# ── Summary ───────────────────────────────────────────────────────────────────
section "Installation complete"

echo -e "
  ${BOLD}VectorGuard is installed.${RESET}

  Binary:    $INSTALL_DIR/vectorguard
  Config:    $CONFIG_DIR/config.toml
  Rules:     $RULES_DIR/

  ${BOLD}Useful commands:${RESET}
    View logs:      journalctl -u vectorguard -f
    Service status: systemctl status vectorguard
    Reload config:  systemctl reload-or-restart vectorguard
    Edit config:    \$EDITOR $CONFIG_DIR/config.toml
    Run manually:   sudo vectorguard --config $CONFIG_DIR/config.toml

  ${BOLD}To uninstall:${RESET}
    sudo bash uninstall.sh
"
