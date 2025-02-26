.PHONY: build
build: build-release build-docs

.PHONY: build-release
build-release:
	cargo build --release

.PHONY:build-docs
build-docs:
	cargo run --release -- docs --output cli-docs.md

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings
	
.PHONY: typos
typos:
	typos # run typo checker from crate-ci/typos

.PHONY: test
test: fmt lint
	cargo test --workspace --bins

.PHONY: e2e-tests
e2e-tests:
	cargo test --test '*'
	
.PHONY: coverage
coverage:
	cargo llvm-cov --html

.PHONY: clean
clean:
	cargo clean

.PHONY: tag
tag:
	@git tag "${TAG}" || (echo "Tag ${TAG} already exists. If you want to retag, delete it manually and re-run this command" && exit 1)
	@git-chglog --output CHANGELOG.md
	@git commit -m 'Update CHANGELOG.md' -- CHANGELOG.md
	@git tag -f "${TAG}"
