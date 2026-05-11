#!/usr/bin/env bash
# CVE-2021-4034 (PwnKit) — local privilege escalation via /usr/bin/pkexec.
# We alert on non-root execs of pkexec.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2021-4034 (PwnKit): non-root pkexec exec"

install_rule "pwnkit-pkexec" '
[[rules]]
name            = "pwnkit-nonroot-pkexec"
action          = "alert"
match_exec_path = ["/usr/bin/pkexec"]
'

start_vectorguard || exit 1

# Drop privs and try to exec pkexec. We don'\''t care whether pkexec is
# installed — the eBPF exec event fires the moment execve is entered.
if id nobody >/dev/null 2>&1; then
    su -s /bin/sh nobody -c "/usr/bin/pkexec --version" 2>/dev/null || true
else
    /usr/bin/pkexec --version 2>/dev/null || true
fi

assert_action_for_rule "pwnkit-nonroot-pkexec" "Alerted" 6

scenario_summary "$0"
