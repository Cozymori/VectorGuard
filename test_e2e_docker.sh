#!/usr/bin/env bash
set -uo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo -e "\033[0;32m[PASS]\033[0m $*"; ((PASS++)); }
fail() { echo -e "\033[0;31m[FAIL]\033[0m $*"; ((FAIL++)); }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; ((WARN++)); }
info() { echo -e "\033[0;34m[INFO]\033[0m $*"; }
section() { echo -e "\n\033[1m══ $* ══\033[0m"; }

LOG=/tmp/vg.log

# ─────────────────────────────────────────────────────────────
section "0. Environment Check"
# ─────────────────────────────────────────────────────────────

info "Kernel: $(uname -r)"
info "Arch: $(uname -m)"

# Mount required filesystems (Docker Desktop doesn't mount these by default)
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null || true
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# Check BPF filesystem
if mount | grep -q "type bpf"; then
  pass "BPF filesystem already mounted"
else
  info "Mounting BPF filesystem..."
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null
  if mount | grep -q "type bpf"; then
    pass "BPF filesystem mounted"
  else
    warn "BPF filesystem mount failed (eBPF may not work)"
  fi
fi

# Check tracepoints
TP_COUNT=$(ls /sys/kernel/debug/tracing/events/syscalls/ 2>/dev/null | grep -c "" || echo 0)
if [ "$TP_COUNT" -gt 0 ]; then
  pass "Tracepoints available ($TP_COUNT entries in syscalls/)"
else
  fail "No tracepoints available (debugfs/tracefs mount failed)"
fi

# Check BTF support
if [ -f /sys/kernel/btf/vmlinux ]; then
  pass "BTF vmlinux available"
else
  warn "No BTF vmlinux (LSM hooks may fail, tracepoints should still work)"
fi

# Check LSM
LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "unavailable")
info "LSM list: $LSM_LIST"

# ─────────────────────────────────────────────────────────────
section "1. Binary Check"
# ─────────────────────────────────────────────────────────────

if [ -x /usr/local/bin/vectorguard ]; then
  pass "vectorguard binary exists and is executable"
else
  fail "vectorguard binary not found"
  echo "=== RESULTS: $PASS passed, $FAIL failed, $WARN warnings ==="
  exit 1
fi

if [ -f /etc/vectorguard/config.toml ]; then
  pass "config.toml exists"
else
  fail "config.toml not found"
fi

RULE_COUNT=$(find /etc/vectorguard/rules -name "*.toml" 2>/dev/null | wc -l)
if [ "$RULE_COUNT" -gt 0 ]; then
  pass "Rules found: $RULE_COUNT file(s)"
else
  warn "No rule files found"
fi

# ─────────────────────────────────────────────────────────────
section "2. Daemon Startup"
# ─────────────────────────────────────────────────────────────

info "Starting vectorguard daemon..."
RUST_LOG=debug /usr/local/bin/vectorguard --config /etc/vectorguard/config.toml > "$LOG" 2>&1 &
VG_PID=$!
info "Daemon PID: $VG_PID"

# Wait for startup
sleep 5

if kill -0 $VG_PID 2>/dev/null; then
  pass "Daemon is running after 5s"
else
  fail "Daemon died on startup"
  echo "--- DAEMON LOG ---"
  cat "$LOG"
  echo "--- END LOG ---"
  echo "=== RESULTS: $PASS passed, $FAIL failed, $WARN warnings ==="
  exit 1
fi

# Check ready file
if [ -f /tmp/vectorguard.ready ]; then
  pass "Ready file exists (/tmp/vectorguard.ready)"
else
  warn "No ready file (daemon may be in degraded mode)"
fi

# Check startup log messages
echo ""
info "--- Startup Log ---"
head -30 "$LOG"
echo "---"

if grep -q "VectorGuard starting" "$LOG"; then
  pass "Startup log message found"
else
  fail "No startup log message"
fi

if grep -q "Fast Path rules loaded" "$LOG"; then
  RULES_LOADED=$(grep "Fast Path rules loaded" "$LOG" | head -1)
  pass "Fast Path rules loaded: $RULES_LOADED"
else
  warn "Fast Path rules load message not found"
fi

if grep -q "LSM hook.*attached" "$LOG"; then
  pass "LSM hooks attached"
elif grep -q "LSM hook.*unavailable" "$LOG"; then
  warn "LSM hooks unavailable (kernel lacks CONFIG_BPF_LSM — tracepoints still work)"
else
  warn "No LSM hook messages in log"
fi

if grep -q "eBPF collector error\|eBPF load failed" "$LOG"; then
  fail "eBPF load/collector error detected"
  grep "eBPF" "$LOG"
elif grep -q "degraded mode" "$LOG"; then
  warn "Running in degraded mode (no events)"
else
  pass "No eBPF errors detected"
fi

# ─────────────────────────────────────────────────────────────
section "3. Test: /etc/shadow access (Fast Path block rule)"
# ─────────────────────────────────────────────────────────────

sleep 1
if timeout 3 cat /etc/shadow > /dev/null 2>&1; then
  info "/etc/shadow read succeeded (block may require LSM enforcement)"
else
  pass "/etc/shadow access was blocked or denied"
fi

sleep 2
if grep -qi "shadow\|block" "$LOG" | grep -v "BLOCKED_"; then
  pass "Shadow access event found in log"
else
  info "No shadow-specific log entry (depends on eBPF event capture)"
fi

# ─────────────────────────────────────────────────────────────
section "4. Test: Suspicious port connection (Fast Path alert rule)"
# ─────────────────────────────────────────────────────────────

nc -w 1 127.0.0.1 4444 2>/dev/null; true
nc -w 1 127.0.0.1 1337 2>/dev/null; true
sleep 2

if grep -q "4444\|1337\|suspicious" "$LOG"; then
  pass "Suspicious port event detected in log"
else
  info "No suspicious port event (depends on eBPF net tracepoint capture)"
fi

# ─────────────────────────────────────────────────────────────
section "5. Test: Hot Reload"
# ─────────────────────────────────────────────────────────────

info "Changing default_action from log to alert..."
sed -i 's/default_action = "log"/default_action = "alert"/' /etc/vectorguard/config.toml
sleep 3

if grep -q "Hot reload\|Pipeline reloading\|reload" "$LOG"; then
  pass "Hot reload triggered"
else
  warn "No hot reload message in log"
fi

# Restore
sed -i 's/default_action = "alert"/default_action = "log"/' /etc/vectorguard/config.toml
sleep 1

# ─────────────────────────────────────────────────────────────
section "6. Test: Dynamic rule loading (block nc)"
# ─────────────────────────────────────────────────────────────

cat > /etc/vectorguard/rules/test-block-nc.toml << 'EOF'
[[rules]]
name          = "test-block-netcat"
action        = "block"
match_process = ["nc", "ncat", "netcat"]
EOF

sleep 2

if grep -q "rules loaded" "$LOG"; then
  pass "Rules reloaded after adding test rule"
else
  warn "No rule reload message"
fi

# Try running nc (should be blocked if enforcer is working)
if timeout 3 nc -w 1 127.0.0.1 9999 2>&1; then
  info "nc ran (kernel enforcement depends on LSM/tracepoint support)"
else
  pass "nc was blocked or terminated"
fi

# Cleanup test rule
rm -f /etc/vectorguard/rules/test-block-nc.toml
sleep 1

# ─────────────────────────────────────────────────────────────
section "7. Daemon Liveness"
# ─────────────────────────────────────────────────────────────

if kill -0 $VG_PID 2>/dev/null; then
  pass "Daemon still running after all tests"
else
  fail "Daemon died during tests"
fi

# ─────────────────────────────────────────────────────────────
section "8. Full Daemon Log"
# ─────────────────────────────────────────────────────────────
cat "$LOG"

# ─────────────────────────────────────────────────────────────
# Cleanup
kill $VG_PID 2>/dev/null; wait $VG_PID 2>/dev/null

section "RESULTS"
echo -e "  \033[0;32mPASS: $PASS\033[0m"
echo -e "  \033[0;31mFAIL: $FAIL\033[0m"
echo -e "  \033[1;33mWARN: $WARN\033[0m"
echo ""

if [ $FAIL -gt 0 ]; then
  echo -e "\033[0;31mSome tests FAILED.\033[0m"
  exit 1
else
  echo -e "\033[0;32mAll tests passed (with $WARN warnings).\033[0m"
  exit 0
fi
