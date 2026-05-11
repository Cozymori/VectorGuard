#!/usr/bin/env bash
# CVE-2022-0847 (Dirty Pipe) — arbitrary write to read-only files. The
# common post-exploit pattern is writing /etc/passwd / /etc/shadow.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2022-0847 (Dirty Pipe): sensitive file write attempt"

install_rule "dirty-pipe-sensitive-write" '
[[rules]]
name              = "dirty-pipe-sensitive-write"
action            = "block"
match_path_prefix = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
'

start_vectorguard || exit 1

# A normal write attempt — we don'\''t actually exploit Dirty Pipe, we
# just trigger the openat() that the rule looks for.
(echo "x:y:z" >> /etc/passwd) 2>/dev/null || true
(cat > /etc/shadow.tmp <<< "test") 2>/dev/null || true
(touch /etc/sudoers.d/test-vg) 2>/dev/null || true

assert_action_for_rule "dirty-pipe-sensitive-write" "Blocked" 6

# Clean up any side effects from our own writes.
rm -f /etc/sudoers.d/test-vg /etc/shadow.tmp 2>/dev/null || true

scenario_summary "$0"
