BINDIR ?= bin
# if change the version used, remember to update the default version used for
# Windows in the release workflow
SBOM_GENERATOR_TOOL_VERSION ?= v0.0.15
SBOM_GENERATOR_TOOL_ARCH ?= linux-amd64

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

.PHONY: e2e-test
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

bin:
	mkdir $(BINDIR)

.PHONY: download-spdx-sbom-generator
download-spdx-sbom-generator: bin
	curl -L -o $(BINDIR)/spdx-sbom-generator-$(SBOM_GENERATOR_TOOL_VERSION)-$(SBOM_GENERATOR_TOOL_ARCH).tar.gz https://github.com/opensbom-generator/spdx-sbom-generator/releases/download/$(SBOM_GENERATOR_TOOL_VERSION)/spdx-sbom-generator-$(SBOM_GENERATOR_TOOL_VERSION)-$(SBOM_GENERATOR_TOOL_ARCH).tar.gz
	tar -xf ./$(BINDIR)/spdx-sbom-generator-$(SBOM_GENERATOR_TOOL_VERSION)-$(SBOM_GENERATOR_TOOL_ARCH).tar.gz --directory $(BINDIR)

.PHONY: sbom
sbom:
	./$(BINDIR)/spdx-sbom-generator -f json
