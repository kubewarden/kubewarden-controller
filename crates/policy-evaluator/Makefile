KUBE_API_VERSION?=1.30

.PHONY: build
build:
	K8S_OPENAPI_ENABLED_VERSION=$(KUBE_API_VERSION) cargo build --release

.PHONY: fmt
fmt:
	K8S_OPENAPI_ENABLED_VERSION=$(KUBE_API_VERSION) cargo fmt --all -- --check

.PHONY: lint
lint:
	K8S_OPENAPI_ENABLED_VERSION=$(KUBE_API_VERSION) cargo clippy --workspace -- -D warnings

.PHONY: check
check:
	K8S_OPENAPI_ENABLED_VERSION=$(KUBE_API_VERSION) cargo check --workspace

policy.wasm: 
	cargo build  --target=wasm32-wasip1 --release -p context-aware-test-policy

annotated-policy.wasm: policy.wasm
	kwctl annotate -m crates/context-aware-test-policy/metadata.yml -u README.md -o annotated-policy.wasm target/wasm32-wasip1/release/context_aware_test_policy.wasm
	
.PHONY: typos
typos:
	typos # run typo checker from crate-ci/typos

.PHONY: test
test: fmt lint annotated-policy.wasm
	cargo test --workspace

.PHONY: unit-tests
unit-tests: fmt lint
	cargo test --workspace --lib

.PHONY: integration-tests
integration-tests: fmt lint annotated-policy.wasm
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
