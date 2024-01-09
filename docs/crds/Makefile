ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CRD_REF_DOCS_VER := v0.0.9
CRD_REF_DOCS_BIN := crd-ref-docs
CRD_REF_DOCS := $(BIN_DIR)/$(CRD_REF_DOCS_BIN)

crd-ref-docs: $(CRD_REF_DOCS)

$(CRD_REF_DOCS): ## Install crd-ref-docs
	GOBIN=$(BIN_DIR) go install github.com/elastic/crd-ref-docs@$(CRD_REF_DOCS_VER)

.PHONY: generate
generate:
	$(CRD_REF_DOCS) --log-level INFO --config=config.yml --renderer=markdown --source-path=../../pkg/apis --output-path=CRD-docs-for-docs-repo.md
