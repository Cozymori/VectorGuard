#!/usr/bin/env bash
# =============================================================================
# VectorGuard Uninstaller — bare-metal Linux
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash uninstall.sh"

echo -e "\n${BOLD}VectorGuard Uninstaller${RESET}"
echo "This will remove: binary, config, rules, systemd service."
read -rp "Continue? [y/N] " yn
[[ "${yn,,}" == "y" ]] || { echo "Aborted."; exit 0; }

# Stop and disable service
if systemctl is-active --quiet vectorguard 2>/dev/null; then
  systemctl stop vectorguard
  ok "Service stopped"
fi
if systemctl is-enabled --quiet vectorguard 2>/dev/null; then
  systemctl disable vectorguard
  ok "Service disabled"
fi
rm -f /etc/systemd/system/vectorguard.service
systemctl daemon-reload
ok "systemd unit removed"

# Binary
rm -f /usr/local/bin/vectorguard
ok "Binary removed"

# Config (ask before deleting — may contain user customizations)
if [[ -d /etc/vectorguard ]]; then
  read -rp "Remove /etc/vectorguard (config + rules)? [y/N] " yn2
  if [[ "${yn2,,}" == "y" ]]; then
    rm -rf /etc/vectorguard
    ok "Config directory removed"
  else
    warn "Config kept at /etc/vectorguard"
  fi
fi

# Qdrant Docker container (optional)
if command -v docker &>/dev/null && docker ps -a --format '{{.Names}}' | grep -q "^qdrant$"; then
  read -rp "Remove Qdrant Docker container + volume? [y/N] " yn3
  if [[ "${yn3,,}" == "y" ]]; then
    docker rm -f qdrant 2>/dev/null || true
    docker volume rm qdrant_storage 2>/dev/null || true
    ok "Qdrant container and volume removed"
  else
    warn "Qdrant container kept"
  fi
fi

echo -e "\n${GREEN}VectorGuard uninstalled.${RESET}"
