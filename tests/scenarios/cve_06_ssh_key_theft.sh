#!/usr/bin/env bash
# SSH private-key exfiltration attempt — read under */.ssh/.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "SSH key theft: read of .ssh/"

install_rule "ssh-key-read" '
[[rules]]
name              = "ssh-key-read"
action            = "alert"
match_path_prefix = ["/root/.ssh/", "/home/"]
'

start_vectorguard || exit 1

mkdir -p /root/.ssh
echo "fake-priv-key" > /root/.ssh/id_rsa_test
cat /root/.ssh/id_rsa_test >/dev/null 2>&1 || true

assert_action_for_rule "ssh-key-read" "Alerted" 6

rm -f /root/.ssh/id_rsa_test

scenario_summary "$0"
