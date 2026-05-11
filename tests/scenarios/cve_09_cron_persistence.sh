#!/usr/bin/env bash
# Cron persistence — attackers often plant a job in /etc/cron.d/ to keep
# access. Block writes to the canonical cron locations.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "Cron persistence: write to /etc/cron.d/"

install_rule "cron-persistence" '
[[rules]]
name              = "cron-persistence-write"
action            = "block"
match_path_prefix = ["/etc/cron.d/", "/etc/crontab", "/var/spool/cron/"]
'

start_vectorguard || exit 1

mkdir -p /etc/cron.d
(echo "* * * * * root /tmp/x" > /etc/cron.d/vg-test) 2>/dev/null || true

assert_action_for_rule "cron-persistence-write" "Blocked" 6

rm -f /etc/cron.d/vg-test

scenario_summary "$0"
