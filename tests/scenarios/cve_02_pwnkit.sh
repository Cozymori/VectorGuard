#!/usr/bin/env bash
# CVE-2021-4034 (PwnKit) — local privilege escalation via /usr/bin/pkexec.
# We alert on non-root execs of pkexec.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2021-4034 (PwnKit): non-root pkexec exec"

install_rule "pwnkit-pkexec" '
[[rules]]
name          = "pwnkit-nonroot-pkexec"
action        = "alert"
match_process = ["pkexec"]
'

start_vectorguard || exit 1

# Rule fires on any process named "pkexec". Many minimal hosts do not ship
# pkexec (RHEL/Rocky base, Alpine, distroless), so we fabricate one by
# copying /bin/true to /tmp/pkexec. The kernel sets comm from the binary's
# basename, so the new process has comm="pkexec" and the exec event will
# match on the rule.
PKEXEC_BIN=$(make_named_binary pkexec /bin/true)
"$PKEXEC_BIN" 2>/dev/null || true

assert_action_for_rule "pwnkit-nonroot-pkexec" "Alerted" 6

scenario_summary "$0"
