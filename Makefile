# VectorGuard test runner.
# Tiered targets:
#   make test-unit         # cargo test (in-process unit tests)
#   make test-integration  # cargo test --test '*' (integration tests)
#   make test-e2e          # existing Docker daemon smoke test
#   make test-scenarios    # all CVE-style scenarios in Docker (use SCENARIO=NN for one)
#   make test              # unit + integration + e2e + scenarios
#   make test-fast         # unit + integration only (no Docker)
#   make check             # cargo check + clippy + fmt --check
#
# Host build of vectorguard requires bypassing the workspace's default
# bpfel-unknown-none target. We hardcode --target to the host triple.

HOST_TARGET := $(shell rustc -vV | awk '/host:/ {print $$2}')
CARGO_HOST  := cargo --color=always
HOST_FLAGS  := --target $(HOST_TARGET) -p vectorguard

DOCKER_IMG  := vectorguard-test

.PHONY: test test-fast test-unit test-integration test-e2e test-scenarios check fmt clippy clean

test: test-unit test-integration test-e2e test-scenarios

test-fast: test-unit test-integration

test-unit:
	$(CARGO_HOST) test $(HOST_FLAGS) --lib --bins

test-integration:
	$(CARGO_HOST) test $(HOST_FLAGS) --tests

# Existing daemon smoke test inside a privileged container.
test-e2e:
	docker build -f Dockerfile.test -t $(DOCKER_IMG) .
	docker run --rm --privileged --pid=host \
		-v /sys/fs/bpf:/sys/fs/bpf \
		$(DOCKER_IMG) /test_e2e_docker.sh

# CVE-style scenarios. Pass SCENARIO=04 to run just one.
test-scenarios:
	docker build -f Dockerfile.test -t $(DOCKER_IMG) .
	docker run --rm --privileged --pid=host \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-v $(PWD)/tests/scenarios:/tests/scenarios:ro \
		-e SCENARIO=$(SCENARIO) \
		$(DOCKER_IMG) bash /tests/scenarios/run_all.sh

check: fmt clippy
	$(CARGO_HOST) check $(HOST_FLAGS) --all-targets

fmt:
	$(CARGO_HOST) fmt --check

clippy:
	$(CARGO_HOST) clippy $(HOST_FLAGS) --all-targets -- -D warnings

clean:
	$(CARGO_HOST) clean
