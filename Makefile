
# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.23
# Binary directory
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# Tools binaries
CONTROLLER_GEN_VER := v0.8.0
CONTROLLER_GEN_BIN := controller-gen
CONTROLLER_GEN := $(BIN_DIR)/$(CONTROLLER_GEN_BIN)

KUSTOMIZE_VER := v4.5.2
KUSTOMIZE_BIN := kustomize
KUSTOMIZE := $(BIN_DIR)/$(KUSTOMIZE_BIN)

SETUP_ENVTEST_VER := v0.0.0-20211110210527-619e6b92dab9
SETUP_ENVTEST_BIN := setup-envtest
SETUP_ENVTEST := $(abspath $(BIN_DIR)/$(SETUP_ENVTEST_BIN))

GOLANGCI_LINT_VER := v1.52.2
GOLANGCI_LINT_BIN := golangci-lint
GOLANGCI_LINT := $(BIN_DIR)/$(GOLANGCI_LINT_BIN)

all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

## @ Tools

controller-gen: $(CONTROLLER_GEN) ## Install a local copy of controller-gen.
kustomize: $(KUSTOMIZE) ## Install a local copy of kustomize.
setup-envtest: $(SETUP_ENVTEST) ## Install a local copy of setup-envtest.
golangci-lint: $(GOLANGCI_LINT) ## Install a local copy of golang ci-lint.

$(CONTROLLER_GEN): ## Install controller-gen.
	GOBIN=$(BIN_DIR) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VER)

$(KUSTOMIZE): ## Install kustomize.
	GOBIN=$(BIN_DIR) go install sigs.k8s.io/kustomize/kustomize/v4@$(KUSTOMIZE_VER)

$(SETUP_ENVTEST): ## Install setup-envtest.
	GOBIN=$(BIN_DIR) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VER)

$(GOLANGCI_LINT): ## Install golangci-lint.
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER)

##@ Development

manifests: $(CONTROLLER_GEN)  ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

generate: $(CONTROLLER_GEN) ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

.PHONY: test
test: unit-tests integration-tests ## Run tests.

.PHONY: setup-envtest
setup-envtest: $(SETUP_ENVTEST) # Build setup-envtest
	@if [ $(shell go env GOOS) == "darwin" ]; then \
		$(eval KUBEBUILDER_ASSETS := $(shell $(SETUP_ENVTEST) use --use-env -p path --arch amd64 $(ENVTEST_K8S_VERSION))) \
		echo "kube-builder assets set using darwin OS"; \
	else \
		$(eval KUBEBUILDER_ASSETS := $(shell $(SETUP_ENVTEST) use --use-env -p path $(ENVTEST_K8S_VERSION))) \
		echo "kube-builder assets set using other OS"; \
	fi

.PHONY: unit-tests
unit-tests: manifests generate fmt vet setup-envtest ## Run unit tests.
	KUBEBUILDER_ASSETS="$(KUBEBUILDER_ASSETS)" go test ./internal/... -test.v -coverprofile cover.out
	KUBEBUILDER_ASSETS="$(KUBEBUILDER_ASSETS)" go test ./pkg/... -test.v -coverprofile cover.out

.PHONY: setup-envtest integration-tests
integration-tests: manifests generate fmt vet setup-envtest ## Run integration tests.
	ACK_GINKGO_DEPRECATIONS=2.12.0 KUBEBUILDER_ASSETS="$(KUBEBUILDER_ASSETS)" go test ./pkg/... ./controllers/... -ginkgo.v -ginkgo.progress -test.v -coverprofile cover.out

.PHONY: generate-crds
generate-crds: $(KUSTOMIZE) manifests kustomize ## generate final crds with kustomize. Normally shipped in Helm charts.
	mkdir -p generated-crds
	$(KUSTOMIZE) build config/crd -o generated-crds # If -o points to a folder, kustomize saves them as several files instead of 1

##@ Build

build: generate fmt vet ## Build manager binary.
	go build -o bin/manager .

run: manifests generate fmt vet ## Run a controller from your host.
	go run . -deployments-namespace kubewarden --default-policy-server default

docker-build: test ## Build docker image with the manager.
	docker build -t ${IMG} .

docker-push: ## Push docker image with the manager.
	docker push ${IMG}

##@ Deployment

install: $(KUSTOMIZE) manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

uninstall: $(KUSTOMIZE) manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

deploy: $(KUSTOMIZE) manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

undeploy: $(KUSTOMIZE) ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	bash -c "./scripts/removeFinalizersFromCRDs.sh"
	$(KUSTOMIZE) build config/default | kubectl delete -f -

##@ Release

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
