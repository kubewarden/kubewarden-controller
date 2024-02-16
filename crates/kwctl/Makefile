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
	cargo test --workspace --bins

.PHONY: e2e-tests
e2e-tests:
	cargo test --test '*'
	
.PHONY: coverage
coverage: coverage-unit-tests coverage-e2e-tests
	
.PHONY: coverage-unit-tests
coverage-unit-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --bins --follow-exec \
		--out xml --out html --output-dir coverage/unit-tests
	
.PHONY: coverage-e2e-tests
coverage-e2e-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --test e2e --follow-exec \
		--out xml --out html --output-dir coverage/e2e-tests

.PHONY: clean
clean:
	cargo clean

.PHONY: tag
tag:
	@git tag "${TAG}" || (echo "Tag ${TAG} already exists. If you want to retag, delete it manually and re-run this command" && exit 1)
	@git-chglog --output CHANGELOG.md
	@git commit -m 'Update CHANGELOG.md' -- CHANGELOG.md
	@git tag -f "${TAG}"
