# Makefile for aggregating all Rust crates operations
# This delegates to individual crate Makefiles where needed

# Crates that have their own Makefiles with special requirements
CRATE_DIRS := policy-evaluator policy-server kwctl policy-fetcher burrego

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy --workspace -- -D warnings

.PHONY: lint-fix
lint-fix:
	cargo clippy --workspace --fix --allow-dirty --allow-staged

.PHONY: check
check:
	cargo check --workspace

# Test targets - policy-evaluator needs special handling due to WASM fixtures
.PHONY: test
test:
	$(MAKE) -C policy-evaluator test
	$(MAKE) -C policy-server test
	$(MAKE) -C kwctl test
	$(MAKE) -C policy-fetcher test
	$(MAKE) -C burrego test

.PHONY: unit-tests
unit-tests:
	$(MAKE) -C policy-evaluator unit-tests
	$(MAKE) -C policy-server unit-tests
	$(MAKE) -C kwctl unit-tests
	$(MAKE) -C policy-fetcher unit-tests
	$(MAKE) -C burrego unit-tests

.PHONY: e2e-tests
e2e-tests:
	$(MAKE) -C policy-evaluator integration-tests
	$(MAKE) -C policy-server integration-tests
	$(MAKE) -C kwctl e2e-tests
	$(MAKE) -C policy-fetcher integration-tests
	$(MAKE) -C burrego e2e-tests

# Coverage targets
.PHONY: coverage
coverage: coverage-unit-tests coverage-e2e-tests

.PHONY: coverage-unit-tests
coverage-unit-tests:
	$(MAKE) -C policy-evaluator coverage-unit-tests
	$(MAKE) -C policy-server coverage-unit-tests
	$(MAKE) -C policy-fetcher coverage-unit-tests

.PHONY: coverage-e2e-tests
coverage-e2e-tests:
	$(MAKE) -C policy-evaluator coverage-integration-tests
	$(MAKE) -C policy-server coverage-integration-tests
	$(MAKE) -C policy-fetcher coverage-integration-tests

.PHONY: clean
clean:
	cargo clean
	$(foreach dir,$(CRATE_DIRS),$(MAKE) -C $(dir) clean;)

.PHONY: typos
typos:
	typos
