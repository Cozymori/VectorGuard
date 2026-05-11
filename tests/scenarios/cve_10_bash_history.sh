#!/usr/bin/env bash
# bash history evasion — clearing or truncating ~/.bash_history is a
# common post-exploit cleanup step.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "bash history evasion: truncate /root/.bash_history"

install_rule "history-evasion" '
[[rules]]
name              = "bash-history-evasion"
action            = "alert"
match_path_prefix = ["/root/.bash_history", "/home/"]
'

start_vectorguard || exit 1

mkdir -p /root
echo "previous-command" > /root/.bash_history
: > /root/.bash_history   # truncating open triggers openat with O_TRUNC

assert_action_for_rule "bash-history-evasion" "Alerted" 6

rm -f /root/.bash_history

scenario_summary "$0"
