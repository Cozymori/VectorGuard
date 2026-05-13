#!/usr/bin/env bash
# Run every CVE scenario in tests/scenarios/cve_*.sh and roll up results.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0
FAILED_SCENARIOS=()

# Allow running a single scenario by number prefix, e.g.: SCENARIO=04
FILTER="${SCENARIO:-}"

shopt -s nullglob
for script in "$SCRIPT_DIR"/cve_*.sh; do
    name="$(basename "$script")"
    if [[ -n "$FILTER" && "$name" != cve_${FILTER}_* ]]; then
        continue
    fi

    printf '\n\033[1;36m═══ Running %s ═══\033[0m\n' "$name"

    output="$(bash "$script" 2>&1)"
    rc=$?
    echo "$output"

    # record_pass/fail/warn in lib.sh emit ANSI color codes before the
    # tag, so the bracketed marker is not at column 0. Strip CSI sequences
    # before counting.
    plain=$(sed 's/\x1b\[[0-9;]*m//g' <<<"$output")
    pass=$(grep -c '^\[PASS\]' <<<"$plain" || true)
    fail=$(grep -c '^\[FAIL\]' <<<"$plain" || true)
    warn=$(grep -c '^\[WARN\]' <<<"$plain" || true)
    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))
    TOTAL_WARN=$((TOTAL_WARN + warn))

    if (( rc != 0 || fail > 0 )); then
        FAILED_SCENARIOS+=("$name")
    fi
done

printf '\n\033[1m═══ TOTAL: %d pass, %d fail, %d warn ═══\033[0m\n' \
    "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_WARN"

if (( ${#FAILED_SCENARIOS[@]} > 0 )); then
    printf '\033[0;31mFailed scenarios:\033[0m\n'
    for s in "${FAILED_SCENARIOS[@]}"; do
        printf '  - %s\n' "$s"
    done
    exit 1
fi

printf '\033[0;32mAll scenarios passed.\033[0m\n'
