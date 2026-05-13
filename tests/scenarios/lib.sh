#!/usr/bin/env bash
#
# Shared helpers for VectorGuard CVE-style scenario tests.
# Source from each tests/scenarios/*.sh script.

set -uo pipefail

# Counters — `record_pass`, `record_fail`, etc. update these.
SCENARIO_PASS=0
SCENARIO_FAIL=0
SCENARIO_WARN=0

VG_LOG="${VG_LOG:-/tmp/vg-scenario.log}"
VG_PID_FILE="${VG_PID_FILE:-/tmp/vg-scenario.pid}"
VG_CONFIG="${VG_CONFIG:-/etc/vectorguard/config.toml}"
VG_RULES_DIR="${VG_RULES_DIR:-/etc/vectorguard/rules}"
VG_INCIDENTS="${VG_INCIDENTS:-/var/log/vectorguard/incidents.jsonl}"

# ── Output helpers ───────────────────────────────────────────────

color_pass() { printf '\033[0;32m[PASS]\033[0m %s\n' "$*"; }
color_fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }
color_warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
color_info() { printf '\033[0;34m[INFO]\033[0m %s\n' "$*"; }

record_pass() { color_pass "$*"; SCENARIO_PASS=$((SCENARIO_PASS + 1)); }
record_fail() { color_fail "$*"; SCENARIO_FAIL=$((SCENARIO_FAIL + 1)); }
record_warn() { color_warn "$*"; SCENARIO_WARN=$((SCENARIO_WARN + 1)); }

section() {
    printf '\n\033[1m── %s ──\033[0m\n' "$*"
}

# ── VectorGuard lifecycle ────────────────────────────────────────

# Move default.toml aside so only scenario-installed rules apply. This
# prevents broad default rules (e.g. alert-suspicious-port covering ports
# 4444/1337/...) from shadowing a scenario's narrower rule under
# first-match-wins evaluation.
disable_default_rules() {
    if [[ -f "$VG_RULES_DIR/default.toml" ]]; then
        mv "$VG_RULES_DIR/default.toml" "$VG_RULES_DIR/.default.toml.disabled"
    fi
}

enable_default_rules() {
    if [[ -f "$VG_RULES_DIR/.default.toml.disabled" ]]; then
        mv "$VG_RULES_DIR/.default.toml.disabled" "$VG_RULES_DIR/default.toml"
    fi
}

# Make a real binary at /tmp/<name> by copying /bin/bash (or any binary
# given as the second argument), so exec'ing it sets the kernel's comm to
# <name>. The kernel derives comm from the *basename* of the executed file
# (truncated to 15 chars), so the file must be named exactly <name> — a
# "scenario-<name>" prefix would produce comm="scenario-<name>".
#
# Used when a scenario wants to trigger rules that match on process name
# (e.g. "java", "nginx", "pkexec") but the host has no such binary.
# `exec -a` only rewrites argv[0] and does not change comm, so a real
# file is required.
#
# Tracked in SCENARIO_NAMED_BINS so clean_exit can remove them.
declare -a SCENARIO_NAMED_BINS=()
make_named_binary() {
    local name="$1"
    local src="${2:-/bin/bash}"
    local path="/tmp/$name"
    cp "$src" "$path"
    chmod +x "$path"
    SCENARIO_NAMED_BINS+=("$path")
    printf '%s\n' "$path"
}

cleanup_named_binaries() {
    local p
    for p in "${SCENARIO_NAMED_BINS[@]:-}"; do
        [[ -n "$p" ]] && rm -f "$p"
    done
    SCENARIO_NAMED_BINS=()
}

# Start the daemon with whatever config is in place. Captures PID to file.
start_vectorguard() {
    if [[ ! -x /usr/local/bin/vectorguard ]]; then
        record_fail "vectorguard binary not installed"
        return 1
    fi
    disable_default_rules
    : > "$VG_LOG"
    RUST_LOG="${RUST_LOG:-info}" /usr/local/bin/vectorguard \
        --config "$VG_CONFIG" > "$VG_LOG" 2>&1 &
    echo $! > "$VG_PID_FILE"
    sleep 4
    local pid
    pid="$(cat "$VG_PID_FILE")"
    if ! kill -0 "$pid" 2>/dev/null; then
        record_fail "daemon died on startup"
        tail -50 "$VG_LOG" >&2
        return 1
    fi
    color_info "daemon started (pid=$pid)"
}

stop_vectorguard() {
    if [[ -f "$VG_PID_FILE" ]]; then
        local pid
        pid="$(cat "$VG_PID_FILE")"
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        rm -f "$VG_PID_FILE"
    fi
}

# ── Rule management ──────────────────────────────────────────────

# install_rule <name> <toml-body>
install_rule() {
    local name="$1"
    local body="$2"
    local path="$VG_RULES_DIR/scenario-${name}.toml"
    mkdir -p "$VG_RULES_DIR"
    printf '%s\n' "$body" > "$path"
    # give hot reload time to pick it up
    sleep 2
}

cleanup_rules() {
    rm -f "$VG_RULES_DIR"/scenario-*.toml 2>/dev/null || true
    sleep 1
}

# ── Incident assertions ──────────────────────────────────────────

# wait_for_incident <rule-name> [timeout-secs]
# Tails the incident log until a record with the given rule name appears.
# Returns 0 if found, 1 if timed out.
wait_for_incident() {
    local rule="$1"
    local timeout="${2:-5}"
    local deadline=$(( $(date +%s) + timeout ))

    while [[ $(date +%s) -lt $deadline ]]; do
        if [[ -f "$VG_INCIDENTS" ]] && grep -q "\"rule\":\"${rule}\"" "$VG_INCIDENTS" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# assert_incident_for_rule <rule-name> [timeout]
assert_incident_for_rule() {
    local rule="$1"
    local timeout="${2:-5}"
    if wait_for_incident "$rule" "$timeout"; then
        record_pass "incident logged for rule '$rule'"
    else
        record_fail "no incident logged for rule '$rule' within ${timeout}s"
        if [[ -f "$VG_INCIDENTS" ]]; then
            color_info "incidents.jsonl tail:"
            tail -20 "$VG_INCIDENTS" >&2 || true
        else
            color_info "incidents.jsonl does not exist"
        fi
    fi
}

# assert_action_for_rule <rule-name> <action> [timeout]
# action is one of: Blocked | Alerted | Killed | Logged
assert_action_for_rule() {
    local rule="$1"
    local action="$2"
    local timeout="${3:-5}"
    if wait_for_incident "$rule" "$timeout"; then
        if grep -q "\"rule\":\"${rule}\".*\"action\":\"${action}\"" "$VG_INCIDENTS" 2>/dev/null \
           || grep -q "\"action\":\"${action}\".*\"rule\":\"${rule}\"" "$VG_INCIDENTS" 2>/dev/null; then
            record_pass "rule '$rule' → action $action"
        else
            record_fail "rule '$rule' fired but action is not $action"
            grep "\"rule\":\"${rule}\"" "$VG_INCIDENTS" >&2 | tail -3 || true
        fi
    else
        record_fail "rule '$rule' did not fire (expected action $action)"
    fi
}

# ── Log assertions ───────────────────────────────────────────────

assert_log_contains() {
    local pattern="$1"
    if grep -qE "$pattern" "$VG_LOG"; then
        record_pass "log matches: $pattern"
    else
        record_fail "log missing: $pattern"
    fi
}

# ── Result summary ───────────────────────────────────────────────

scenario_summary() {
    local name="${1:-scenario}"
    echo
    printf '\033[1m═══ %s: %d pass, %d fail, %d warn ═══\033[0m\n' \
        "$name" "$SCENARIO_PASS" "$SCENARIO_FAIL" "$SCENARIO_WARN"
    if (( SCENARIO_FAIL > 0 )); then
        return 1
    fi
    return 0
}

# Auto-cleanup on exit (each scenario sources this and traps to clean_exit).
clean_exit() {
    local rc=$?
    stop_vectorguard
    cleanup_rules
    cleanup_named_binaries
    enable_default_rules
    exit "$rc"
}
