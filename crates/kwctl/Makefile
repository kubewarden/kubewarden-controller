HYPERFINE := $(shell command -v hyperfine 2> /dev/null)

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

${HOME}/.sigstore/root/targets/fulcio_v1.crt.pem:
	cosign initialize

.PHONY: e2e-test
e2e-test: ${HOME}/.sigstore/root/targets/fulcio_v1.crt.pem
e2e-test:
	sh -c 'cd e2e-tests; bats --print-output-on-failure .'

.PHONY: clean
clean:
	cargo clean

.PHONY: tag
tag:
	@git tag "${TAG}" || (echo "Tag ${TAG} already exists. If you want to retag, delete it manually and re-run this command" && exit 1)
	@git-chglog --output CHANGELOG.md
	@git commit -m 'Update CHANGELOG.md' -- CHANGELOG.md
	@git tag -f "${TAG}"
