#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. install.sh ==="
cd /repo
bash install.sh --no-service --no-qdrant 2>&1 | grep -E "\[OK\]|\[ERROR\]|\[WARN\]|══"

echo ""
echo "=== 2. BPF filesystem mount ==="
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
if mount | grep -q bpf; then
  echo "PASS: bpf mounted"
else
  echo "FAIL: bpf not mounted"
fi

echo ""
echo "=== 3. Start daemon (native_ebpf) ==="
/usr/local/bin/vectorguard --config /etc/vectorguard/config.toml > /tmp/vg.log 2>&1 &
VG_PID=$!
echo "PID: $VG_PID"
sleep 5

echo "--- DAEMON LOG ---"
cat /tmp/vg.log
echo "--- END LOG ---"

if kill -0 $VG_PID 2>/dev/null; then
  echo "PASS: daemon still running after 5s"
else
  echo "FAIL: daemon died"
fi

if ls /tmp/vectorguard.ready 2>/dev/null; then
  echo "PASS: ready file exists"
else
  echo "WARN: no ready file"
fi

echo ""
echo "=== 4. /etc/shadow access (block rule test) ==="
if timeout 3 cat /etc/shadow > /dev/null 2>&1; then
  echo "RESULT: not blocked (action=log, expected without LSM enforcement)"
else
  echo "RESULT: blocked or killed (block rule + LSM working!)"
fi

echo ""
echo "=== 5. Hot reload test ==="
sed -i 's/default_action = "log"/default_action = "alert"/' /etc/vectorguard/config.toml
sleep 2
grep "default_action" /etc/vectorguard/config.toml
if grep -q "Pipeline reloading\|Hot reload" /tmp/vg.log; then
  echo "PASS: hot reload triggered"
else
  echo "WARN: no hot reload in log yet (may need more time)"
fi

echo ""
echo "=== 6. nc block rule test ==="
cat > /etc/vectorguard/rules/test-block-nc.toml << 'EOF'
[[rules]]
name          = "test-block-netcat"
action        = "block"
match_process = ["nc", "ncat", "netcat"]
EOF
sleep 1

apt-get install -y --no-install-recommends netcat-openbsd -qq 2>/dev/null || true
if timeout 3 nc -w1 127.0.0.1 9999 2>&1; then
  echo "RESULT: nc ran (eBPF enforcement depends on kernel support)"
else
  echo "RESULT: nc blocked or refused"
fi

echo ""
echo "=== 7. suspicious port connect test ==="
# Should trigger alert-suspicious-port rule
nc -w1 127.0.0.1 4444 2>/dev/null || true
sleep 1
if grep -q "suspicious-port\|4444" /tmp/vg.log; then
  echo "PASS: suspicious port alert logged"
else
  echo "INFO: no port alert (requires eBPF event capture)"
fi

echo ""
echo "=== 8. Final daemon status ==="
if kill -0 $VG_PID 2>/dev/null; then
  echo "PASS: daemon still running at end of all tests"
else
  echo "FAIL: daemon died during tests"
fi

echo ""
echo "=== Final daemon log ==="
cat /tmp/vg.log

kill $VG_PID 2>/dev/null || true
echo ""
echo "=== ALL TESTS COMPLETE ==="
