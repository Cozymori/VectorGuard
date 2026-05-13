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
name          = "sudoedit-exec"
action        = "alert"
match_process = ["sudoedit"]
'

start_vectorguard || exit 1

# Rule fires on events whose comm is "sudoedit". On hosts where sudoedit
# is installed, the real binary works (kernel sets comm from basename).
# Otherwise we fabricate one — match_process is comm-based, so the binary
# does not need to be the real sudoedit.
if [[ -x /usr/bin/sudoedit ]]; then
    /usr/bin/sudoedit --version >/dev/null 2>&1 || true
else
    SUDOEDIT_BIN=$(make_named_binary sudoedit /bin/true)
    "$SUDOEDIT_BIN" 2>/dev/null || true
fi

assert_action_for_rule "sudoedit-exec" "Alerted" 6

scenario_summary "$0"
