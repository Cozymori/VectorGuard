# Testing VectorGuard

This document covers the tiered test suite and how to run each tier. For project setup and installation, see [README.md](README.md).

## Tiered layout

| Tier | Where | Runs in | Command |
|------|-------|---------|---------|
| **Unit** | `vectorguard/src/**/tests` | Host (any OS) | `make test-unit` |
| **Integration** | `vectorguard/tests/*.rs` | Host (any OS) | `make test-integration` |
| **E2E** | `test_e2e_docker.sh` | Privileged Docker (Linux kernel) | `make test-e2e` |
| **Scenarios** | `tests/scenarios/cve_*.sh` | Privileged Docker (Linux kernel) | `make test-scenarios` |

`make test-fast` runs the host-only tiers (unit + integration). `make test` runs everything.

## Unit tests

In-process tests living next to the code they cover. No Docker, no Linux required. Fast.

```bash
make test-unit
# or directly:
cargo test --target $(rustc -vV | awk '/host:/ {print $2}') --lib --bins
```

Coverage areas:
- `fast_path::rules` — rule evaluation, action mapping
- `scope` — filter combinations, namespace and label matching
- `enforcer` — `comm_key` truncation, `compute_block_keys` filtering
- `incident` — record serialization, async writer round-trip
- `ai_advisor` — response parsing (fenced/raw TOML), pattern key generation
- `slow_path` — `stable_id` determinism, `blend` normalization
- `slow_path::context` — sliding window pruning, recency weighting
- `slow_path::embedder` — local embedder unit vectors, event-to-text formatting
- `config` — TOML round-trip

## Integration tests

End-to-end across modules without eBPF, Qdrant, or external services. Synthesizes `NormalizedEvent` streams and exercises the userspace pipeline.

```bash
make test-integration
```

Files:
- `vectorguard/tests/pipeline.rs` — scope → fast_path → incident with block/alert/exclude variants
- `vectorguard/tests/incident_logger.rs` — concurrent writes, ordering guarantees

## End-to-end (Docker)

Boots the daemon inside a privileged container, attaches real tracepoints, and exercises hot reload and basic detections.

```bash
make test-e2e
```

This is the existing `test_e2e_docker.sh` script. It needs `--privileged` for eBPF and mounts `/sys/fs/bpf`.

## CVE-style scenarios

Each scenario installs a TOML rule, simulates the corresponding attack pattern, then asserts an incident appeared in `/var/log/vectorguard/incidents.jsonl` with the expected action.

```bash
# Run all scenarios
make test-scenarios

# Run a single scenario by number
make test-scenarios SCENARIO=04
```

Currently shipped scenarios:

| #  | Pattern | CVE / class | Action expected |
|----|---------|-------------|-----------------|
| 01 | Log4Shell — webserver execs shell | CVE-2021-44228 | Blocked |
| 02 | PwnKit — non-root pkexec | CVE-2021-4034 | Alerted |
| 03 | Dirty Pipe — /etc/passwd write | CVE-2022-0847 | Blocked |
| 04 | Reverse shell to suspicious port | (class) | Blocked |
| 05 | Cryptominer execution | (class) | Blocked |
| 06 | SSH private-key read | (class) | Alerted |
| 07 | Spring4Shell — Java fetches stage 2 | CVE-2022-22965 | Alerted |
| 08 | sudo baron samedit — sudoedit exec | CVE-2021-3156 | Alerted |
| 09 | Cron persistence — /etc/cron.d write | (class) | Blocked |
| 10 | bash history truncation | (class) | Alerted |
| 11 | Container escape — /proc sensitive read | (class) | Blocked |
| 12 | Webserver outbound to unusual port | (class) | Alerted |

### Adding a new scenario

1. Copy `tests/scenarios/cve_NN_template.sh` (or any existing scenario) to `cve_NN_short_name.sh`.
2. `source "$(dirname "$0")/lib.sh"` and `trap clean_exit EXIT`.
3. `install_rule "name" '<toml>'` — the rule TOML body.
4. `start_vectorguard` — boots the daemon with the system config.
5. Trigger the attack pattern in the simplest way that produces the syscall the rule matches.
6. `assert_action_for_rule "<rule-name>" "<Blocked|Alerted|Logged>"` (default timeout 5 s).
7. `scenario_summary "$0"` to print results.

Run the new script directly first:

```bash
docker run --rm --privileged --pid=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v "$PWD/tests/scenarios:/tests/scenarios:ro" \
  vectorguard-test bash /tests/scenarios/cve_NN_new.sh
```

When green, add it to the README table above and to the SCENARIO filter list if needed.

## Useful helpers in `tests/scenarios/lib.sh`

- `start_vectorguard` / `stop_vectorguard` — daemon lifecycle, log captured to `/tmp/vg-scenario.log`
- `install_rule <name> <toml>` — write a rule into `$VG_RULES_DIR` and wait for hot reload
- `cleanup_rules` — remove all scenario-installed rules
- `wait_for_incident <rule-name> [timeout]` — poll `incidents.jsonl` for a matching record
- `assert_incident_for_rule <rule-name> [timeout]` — pass/fail wrapper around the above
- `assert_action_for_rule <rule-name> <action> [timeout]` — additionally checks the recorded action
- `assert_log_contains <regex>` — match the daemon stderr log

## Notes & caveats

- Path-prefix block rules currently use the detect-and-kill model (tracepoint + SIGKILL); the assertions check for incident-log entries, not whether the syscall ultimately failed. See the [Enforcement model](README.md#enforcement-model) section for why.
- Scenarios that simulate exec by renaming the current shell process (`exec -a <name>`) depend on kernel `task->comm` reflecting the new name. This is reliable on Linux but won't run on macOS.
- The Ubuntu / bare-metal install path is documented in [README.md](README.md#option-2-automated-install-bare-metal-linux). For CI-style runs use the Docker tiers above.
