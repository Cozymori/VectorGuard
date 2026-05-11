#!/usr/bin/env bash
# Container escape — reading sensitive /proc nodes that should never be
# touched from a workload (kcore, sysrq-trigger, kmem).

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "Container escape: sensitive /proc access"

install_rule "container-escape" '
[[rules]]
name              = "container-escape-proc"
action            = "block"
match_path_prefix = ["/proc/kcore", "/proc/kmem", "/proc/sysrq-trigger", "/proc/sys/kernel/"]
'

start_vectorguard || exit 1

cat /proc/sysrq-trigger >/dev/null 2>&1 || true
cat /proc/kcore         >/dev/null 2>&1 || true
cat /proc/sys/kernel/random/uuid >/dev/null 2>&1 || true

assert_action_for_rule "container-escape-proc" "Blocked" 6

scenario_summary "$0"
