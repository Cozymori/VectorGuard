#!/usr/bin/env bash
# Webservers should rarely initiate outbound connections to non-standard
# ports. Anything matching this rule is a strong RCE signal.

set -uo pipefail
source "$(dirname "$0")/lib.sh"
trap clean_exit EXIT

section "Webserver outbound: nginx to unusual port"

install_rule "webserver-outbound" '
[[rules]]
name          = "webserver-outbound-unusual"
action        = "alert"
match_process = ["nginx", "apache2", "httpd", "php-fpm"]
match_port    = [4444, 5555, 6666, 8888, 9999]
'

start_vectorguard || exit 1

# Real binary named "nginx" so the connect event's comm matches the rule.
# bash's /dev/tcp triggers sys_enter_connect against port 8888.
NGINX_BIN=$(make_named_binary nginx)
"$NGINX_BIN" -c "exec 3<>/dev/tcp/127.0.0.1/8888" 2>/dev/null || true

assert_action_for_rule "webserver-outbound-unusual" "Alerted" 6

scenario_summary "$0"
