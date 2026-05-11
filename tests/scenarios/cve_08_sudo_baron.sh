#!/usr/bin/env bash
# CVE-2021-3156 (sudo baron samedit) — heap overflow in sudoedit. We can'\''t
# trigger the bug here, but we can alert on any non-root sudoedit exec,
# which is the post-exploit pattern.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2021-3156 (sudo baron samedit): sudoedit exec"

install_rule "sudoedit-exec" '
[[rules]]
name            = "sudoedit-exec"
action          = "alert"
match_exec_path = ["/usr/bin/sudoedit", "/usr/local/bin/sudoedit"]
'

start_vectorguard || exit 1

if [[ -x /usr/bin/sudoedit ]]; then
    /usr/bin/sudoedit --version >/dev/null 2>&1 || true
else
    # No sudoedit installed — fake an exec to /usr/bin/sudoedit by ln+run.
    ln -sf "$(command -v true)" /tmp/sudoedit
    /tmp/sudoedit 2>/dev/null || true
    rm -f /tmp/sudoedit
fi

assert_action_for_rule "sudoedit-exec" "Alerted" 6

scenario_summary "$0"
