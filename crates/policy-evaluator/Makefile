KUBE_API_VERSION?=1.26

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
	K8S_OPENAPI_ENABLED_VERSION=$(KUBE_API_VERSION) cargo check

.PHONY: test
test: fmt lint
	cargo test --workspace

.PHONY: unit-tests
unit-tests: fmt lint
	cargo test --workspace --lib

.PHONY: integration-tests
integration-tests: fmt lint
	cargo test --test '*'


.PHONY: coverage
coverage: coverage-unit-tests coverage-integration-tests
	
.PHONY: coverage-unit-tests
coverage-unit-tests:
	# integration-tests with llvm need +nightly. Hence, enable +nightly on
	# unit-tests, and use --skip-clean to not recompile on CI if not needed
	cargo +nightly tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --lib --bin --follow-exec \
		--out xml --out html --output-dir coverage/unit-tests
	
.PHONY: coverage-integration-tests
coverage-integration-tests:
	cargo +nightly tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --test integration_test --examples --doc --benches --follow-exec \
		--out xml --out html --output-dir coverage/integration-tests

.PHONY: clean
clean:
	cargo clean
