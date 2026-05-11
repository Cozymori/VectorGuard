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

# Plant a stub binary named "xmrig" that just exits, then run it so the
# kernel comm is "xmrig".
mkdir -p /tmp/vg-fake
printf '#!/bin/sh\nexit 0\n' > /tmp/vg-fake/xmrig
chmod +x /tmp/vg-fake/xmrig
/tmp/vg-fake/xmrig 2>/dev/null || true

assert_action_for_rule "cryptominer-known-binaries" "Blocked" 6

rm -rf /tmp/vg-fake

scenario_summary "$0"
