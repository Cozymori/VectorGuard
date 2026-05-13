#!/usr/bin/env bash
# Cryptominer detection — known miner binary names execed anywhere.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "Cryptominer execution: xmrig-style binary"

install_rule "cryptominer-exec" '
[[rules]]
name          = "cryptominer-known-binaries"
action        = "block"
match_process = ["xmrig", "minerd", "cpuminer", "ethminer"]
'

start_vectorguard || exit 1

# Plant a real binary named "xmrig" and run it so the kernel comm is
# "xmrig". A shebang script would re-exec into /bin/sh and the resulting
# process's comm would be "sh", not "xmrig".
XMRIG_BIN=$(make_named_binary xmrig /bin/true)
"$XMRIG_BIN" 2>/dev/null || true

assert_action_for_rule "cryptominer-known-binaries" "Blocked" 6

scenario_summary "$0"
