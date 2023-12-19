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
unit-test: fmt lint
	cargo test --workspace --lib

.PHONY: integration-tests
integration-tests: fmt lint
	cargo test --test '*'

.PHONY: clean
clean:
	cargo clean
