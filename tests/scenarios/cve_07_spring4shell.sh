#!/usr/bin/env bash
# CVE-2022-22965 (Spring4Shell) — exploited Java services typically spawn
# curl/wget to fetch a second-stage payload. Detect java + network tool.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2022-22965 (Spring4Shell): java fetches second stage"

install_rule "spring4shell-java-fetch" '
[[rules]]
name            = "spring4shell-java-fetch"
action          = "alert"
match_process   = ["java"]
match_exec_path = ["/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc"]
'

start_vectorguard || exit 1

# Rename ourselves to java and exec curl.
(
    exec -a java bash -c "/usr/bin/curl --version >/dev/null 2>&1"
) 2>/dev/null || true

assert_action_for_rule "spring4shell-java-fetch" "Alerted" 6

scenario_summary "$0"
