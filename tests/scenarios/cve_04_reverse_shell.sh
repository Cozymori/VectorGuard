#!/usr/bin/env bash
# Reverse-shell pattern — connect to one of the common attacker ports
# (4444 metasploit default, 1337 leet, 31337 elite).

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "Reverse shell: outbound to suspicious port"

install_rule "rev-shell-port" '
[[rules]]
name       = "rev-shell-suspicious-port"
action     = "block"
match_port = [4444, 1337, 31337]
'

start_vectorguard || exit 1

# nc / bash both produce sys_enter_connect events.
timeout 2 nc -w 1 127.0.0.1 4444  </dev/null 2>/dev/null || true
timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/1337" 2>/dev/null || true

assert_action_for_rule "rev-shell-suspicious-port" "Blocked" 6

scenario_summary "$0"
