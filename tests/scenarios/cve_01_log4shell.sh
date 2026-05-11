#!/usr/bin/env bash
# CVE-2021-44228 (Log4Shell) — exploited services typically spawn /bin/sh
# from the JVM process. Detect by binding "java" + shell exec paths.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2021-44228 (Log4Shell): webserver shell exec"

install_rule "log4shell-webserver-shell" '
[[rules]]
name            = "log4shell-webserver-shell"
action          = "block"
match_process   = ["java", "nginx", "apache2", "httpd"]
match_exec_path = ["/bin/sh", "/bin/bash", "/bin/dash"]
'

start_vectorguard || exit 1

# Simulate a JVM child execing /bin/sh. The simplest reproduction is to
# bash-rename ourselves to "java" and exec /bin/sh. exec replaces the
# process image, so we fork first.
(
    exec -a java bash -c "/bin/sh -c 'true'"
) 2>/dev/null || true

assert_action_for_rule "log4shell-webserver-shell" "Blocked" 6

scenario_summary "$0"
