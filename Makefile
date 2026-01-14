CONTROLLER_TOOLS_VERSION := v0.16.5
ENVTEST_VERSION := release-0.19
ENVTEST_K8S_VERSION := 1.31.0
HELM_VALUES_SCHEMA_JSON_VERSION := v2.3.1

CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
HELM_SCHEMA ?= go run github.com/losisin/helm-values-schema-json/v2@$(HELM_VALUES_SCHEMA_JSON_VERSION)

GO_MOD_SRCS := go.mod go.sum
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

ENVTEST_DIR ?= $(shell pwd)/.envtest

REGISTRY ?= ghcr.io
REPO ?= kubewarden
TAG ?= latest

# Detect architecture for Rust builds
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
	RUST_TARGET := x86_64-unknown-linux-musl
else ifeq ($(ARCH),amd64)
	RUST_TARGET := x86_64-unknown-linux-musl
else ifeq ($(ARCH),aarch64)
	RUST_TARGET := aarch64-unknown-linux-musl
else ifeq ($(ARCH),arm64)
	RUST_TARGET := aarch64-unknown-linux-musl
else
	$(error Unsupported architecture: $(ARCH))
endif

.PHONY: all
all: controller audit-scanner policy-server kwctl

.PHONY: test
test: test-go test-rust

.PHONY: test-go
test-go: vet
	$(GO_BUILD_ENV) CGO_ENABLED=1 KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" go test $$(go list ./... | grep -v /e2e) -race -test.v -coverprofile coverage/cover.out -covermode=atomic

.PHONY: test-rust
test-rust:
	$(MAKE) -C crates test

.PHONY: helm-unittest
helm-unittest:
	helm unittest charts/kubewarden-controller --file "tests/**/*_test.yaml"

.PHONY: test-e2e
test-e2e: controller-image audit-scanner-image policy-server-image
	$(GO_BUILD_ENV) go test ./e2e/ -v

.PHONY: fmt-go
fmt-go:
	$(GO_BUILD_ENV) go fmt ./...

.PHONY: lint-go
lint-go: golangci-lint
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --verbose

.PHONY: lint-go-fix
lint-go-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --fix

.PHONY: vet
vet:
	$(GO_BUILD_ENV) go vet ./...

.PHONY: lint-rust
lint-rust:
	$(MAKE) -C crates lint

.PHONY: lint-rust-fix
lint-rust-fix:
	$(MAKE) -C crates lint-fix

.PHONY: fmt-rust
fmt-rust:
	$(MAKE) -C crates fmt

.PHONY: lint
lint: lint-go lint-rust

CONTROLLER_SRC_DIRS := cmd/controller api internal/controller
CONTROLLER_GO_SRCS := $(shell find $(CONTROLLER_SRC_DIRS) -type f -name '*.go')
CONTROLLER_SRCS := $(GO_MOD_SRCS) $(CONTROLLER_GO_SRCS)
.PHONY: controller
controller: $(CONTROLLER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/controller ./cmd/controller

.PHONY: controller-image
controller-image:
	docker build -f ./Dockerfile.kubewarden-controller \
		-t "$(REGISTRY)/$(REPO)/kubewarden-controller:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/kubewarden-controller:$(TAG)"

AUDIT_SCANNER_SRC_DIRS := cmd/audit-scanner api internal/audit-scanner
AUDIT_SCANNER_GO_SRCS := $(shell find $(AUDIT_SCANNER_SRC_DIRS) -type f -name '*.go')
AUDIT_SCANNER_SRCS := $(GO_MOD_SRCS) $(AUDIT_SCANNER_GO_SRCS)
.PHONY: audit-scanner
audit-scanner: $(AUDIT_SCANNER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/audit-scanner ./cmd/audit-scanner

.PHONY: audit-scanner-image
audit-scanner-image:
	docker build -f ./Dockerfile.audit-scanner \
		-t "$(REGISTRY)/$(REPO)/audit-scanner:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/audit-scanner:$(TAG)"

POLICY_SERVER_SRC_DIRS := crates/policy-server
POLICY_SERVER_SRCS := $(shell find $(POLICY_SERVER_SRC_DIRS) -type f -name '*.rs')
.PHONY: policy-server
policy-server: $(POLICY_SERVER_SRCS) lint-rust
	cross build --target $(RUST_TARGET) --release -p policy-server
	cp ./target/$(RUST_TARGET)/release/policy-server ./bin/policy-server

.PHONY: policy-server-image
policy-server-image:
	docker build -f ./Dockerfile.policy-server \
		-t "$(REGISTRY)/$(REPO)/policy-server:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/policy-server:$(TAG)"

KWCTL_SRC_DIRS := crates/kwctl
KWCTL_SRCS := $(shell find $(KWCTL_SRC_DIRS) -type f -name '*.rs')
.PHONY: kwctl
kwctl: $(KWCTL_SRCS) lint-rust
	cross build --target $(RUST_TARGET) --release -p kwctl
	cp ./target/$(RUST_TARGET)/release/kwctl ./bin/kwctl

.PHONY: generate
generate: generate-controller generate-chart

.PHONY: generate-controller
generate-controller: manifests  ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) object paths="./api/policies/v1"

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects. We use yq to modify the generated files to match our naming and labels conventions.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) rbac:roleName=controller-role crd webhook paths="./api/policies/v1"  paths="./internal/controller" output:crd:artifacts:config=charts/kubewarden-crds/templates output:rbac:artifacts:config=charts/kubewarden-controller/templates

.PHONY: generate-chart
generate-chart: ## Generate Helm chart values schema.
	$(HELM_SCHEMA) --values charts/kubewarden-controller/values.yaml --output charts/kubewarden-controller/values.schema.json

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.5.0

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef
