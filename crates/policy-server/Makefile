SHELL := /bin/bash
IMG ?= policy-server:latest
BINDIR ?= bin
SBOM_GENERATOR_TOOL_VERSION ?= v0.0.15

SOURCE_FILES := $(shell test -e src/ && find src -type f)

target/release/policy-server: $(SOURCE_FILES) Cargo.*
	cargo build --release

.PHONY: build
build: target/release/policy-server

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: test
test: fmt lint
	cargo test --workspace

.PHONY: unit-tests
unit-tests: fmt lint
	cargo test --workspace --lib

.PHONY: integration-test
integration-tests: fmt lint
	cargo test --test '*'

.PHONY: coverage
coverage: coverage-unit-tests coverage-integration-tests
	
.PHONY: coverage-unit-tests
coverage-unit-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --lib --bin --follow-exec \
		--out xml --out html --output-dir coverage/unit-tests
	
.PHONY: coverage-integration-tests
coverage-integration-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --test integration_test --follow-exec \
		--out xml --out html --output-dir coverage/integration-tests

.PHONY: clean
clean:
	cargo clean
	make -C e2e-tests clean

.PHONY: tag
tag:
	@git tag "${TAG}" || (echo "Tag ${TAG} already exists. If you want to retag, delete it manually and re-run this command" && exit 1)
	@git tag -s -a -m "${TAG}"  "${TAG}"

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t ${IMG} .

bin:
	mkdir $(BINDIR)

.PHONY: download-spdx-sbom-generator
download-spdx-sbom-generator: bin
	curl -L -o $(BINDIR)/spdx-sbom-generator-$(SBOM_GENERATOR_TOOL_VERSION)-linux-amd64.tar.gz https://github.com/opensbom-generator/spdx-sbom-generator/releases/download/$(SBOM_GENERATOR_TOOL_VERSION)/spdx-sbom-generator-$(SBOM_GENERATOR_TOOL_VERSION)-linux-amd64.tar.gz
	tar -xf ./$(BINDIR)/spdx-sbom-generator-$(SBOM_GENERATOR_TOOL_VERSION)-linux-amd64.tar.gz --directory $(BINDIR)


.PHONY: sbom
sbom:
	./$(BINDIR)/spdx-sbom-generator -f json
