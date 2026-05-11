# VectorGuard tests

Tiered test layout.

## Tiers

### 1. Unit (`cargo test`)

Pure in-process Rust unit tests inside each module. Run on any host (macOS or Linux), no eBPF, no containers.

```bash
make test-unit
# or directly:
cargo test --target $(rustc -vV | awk '/host:/ {print $2}')
```

Covers: rule evaluation, scope filtering, embedder vector math, context window, incident serialization, ai_advisor parsing, slow_path internals.

### 2. Integration (`tests/integration/*.rs`)

Multi-module tests in the workspace `tests/` directory. Synthesizes `NormalizedEvent`s and exercises the pipeline end-to-end without eBPF or external services.

```bash
make test-integration
```

Covers: pipeline composition (scope → fast_path → incident), incident logger async writer round-trip.

### 3. End-to-end (`test_e2e_docker.sh`)

The existing daemon smoke test. Spins up VectorGuard inside a privileged Docker container, exercises daemon startup, hot reload, and a couple of basic detections.

```bash
make test-e2e
# or:
docker build -f Dockerfile.test -t vectorguard-test .
docker run --rm --privileged --pid=host -v /sys/fs/bpf:/sys/fs/bpf vectorguard-test
```

### 4. CVE-style scenarios (`tests/scenarios/cve_*.sh`)

Each script targets a specific real-world attack pattern. The scenario installs a rule, simulates the attack, then asserts the daemon's incident log contains the expected entry.

These run inside the same Docker image as the E2E suite.

```bash
make test-scenarios               # run them all
make test-scenarios SCENARIO=04   # run a single scenario by number
```

Scenarios are independent of `test_e2e_docker.sh` and re-use shared helpers in `tests/scenarios/lib.sh`.

## Adding a scenario

1. Create `tests/scenarios/cve_NN_short_name.sh`.
2. Source `lib.sh` and `trap clean_exit EXIT`.
3. `install_rule "<name>" '<toml-body>'`.
4. `start_vectorguard`.
5. Trigger the attack pattern.
6. `assert_action_for_rule "<rule-name>" "<Blocked|Alerted>"`.
7. `scenario_summary "$0"`.

See any existing scenario for the canonical shape.

## Notes

- Scenarios assume `/usr/local/bin/vectorguard` is installed and `/etc/vectorguard/{config.toml,rules/}` exist. The test Docker image handles that.
- Path-prefix block rules currently use the detect-and-kill model (tracepoint + SIGKILL). The asserts check incidents in `/var/log/vectorguard/incidents.jsonl`, not whether the syscall ultimately failed — see the [Enforcement model](../README.md#enforcement-model) section in the main README for why.
