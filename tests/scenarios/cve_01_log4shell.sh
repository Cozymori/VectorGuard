#!/usr/bin/env bash
# CVE-2021-44228 (Log4Shell) — exploited services typically spawn /bin/sh
# from the JVM process. Detect by binding "java" + shell exec paths.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "CVE-2021-44228 (Log4Shell): webserver shell exec"

install_rule "log4shell-webserver-shell" '
[[rules]]
name          = "log4shell-webserver-shell"
action        = "block"
match_process = ["java", "nginx", "apache2", "httpd"]
'

start_vectorguard || exit 1

# Simulate a JVM exec'ing a shell. The kernel sets comm from the binary's
# basename, so `exec -a java` is not enough — we need a real binary named
# "java". make_named_binary copies bash to /tmp/java.
JAVA_BIN=$(make_named_binary java)
"$JAVA_BIN" -c "/bin/sh -c 'true'" 2>/dev/null || true

assert_action_for_rule "log4shell-webserver-shell" "Blocked" 6

scenario_summary "$0"
