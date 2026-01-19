.PHONY: build
build:
	cargo build --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: check
check:
	cargo check

policy.wasm: 
	cargo build  --target=wasm32-wasip1 --release -p context-aware-test-policy

annotated-policy.wasm: policy.wasm
	kwctl annotate -m ../context-aware-test-policy/metadata.yml -u ../../README.md -o annotated-policy.wasm ../../target/wasm32-wasip1/release/context_aware_test_policy.wasm
	
.PHONY: typos
typos:
	typos # run typo checker from crate-ci/typos

.PHONY: test
test: fmt lint annotated-policy.wasm
	cargo test

.PHONY: unit-tests
unit-tests:
	cargo test --lib

.PHONY: integration-tests
integration-tests: annotated-policy.wasm
	cargo test --test '*'

.PHONY: coverage
coverage: coverage-unit-tests coverage-integration-tests
	
.PHONY: coverage-unit-tests
coverage-unit-tests:
	# use --skip-clean to not recompile on CI if not needed
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--lib --bin --follow-exec \
		--out xml --out html --output-dir coverage/unit-tests
	
.PHONY: coverage-integration-tests
coverage-integration-tests:
	# use --skip-clean to not recompile on CI if not needed
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--test integration_test --follow-exec \
		--out xml --out html --output-dir coverage/integration-tests

.PHONY: clean
clean:
	cargo clean
