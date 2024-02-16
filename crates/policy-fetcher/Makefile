.PHONY: build
build:
	cargo build --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: test
test: fmt lint
	cargo test --workspace
	
.PHONY: coverage
coverage: coverage-unit-tests
	
.PHONY: coverage-unit-tests
coverage-unit-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --lib --follow-exec \
		--out xml --out html --output-dir coverage/unit-tests
	
.PHONY: coverage-integration-tests
coverage-integration-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --test store --test sources --follow-exec \
		--out xml --out html --output-dir coverage/integration-tests

.PHONY: clean
clean:
	cargo clean
