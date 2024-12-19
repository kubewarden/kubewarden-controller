CRD_REF_DOCS_VER := v0.1.0
CRD_REF_DOCS_BIN := crd-ref-docs
CRD_REF_DOCS := go run github.com/elastic/crd-ref-docs@$(CRD_REF_DOCS_VER)

.PHONY: all
all: markdown asciidoc

.PHONY: markdown
markdown:
	$(CRD_REF_DOCS) --log-level INFO --config=config.yml --renderer=markdown --source-path=../../api --output-path=CRD-docs-for-docs-repo.md

.PHONY: asciidoc
asciidoc:
	$(CRD_REF_DOCS) --log-level INFO --config=config.yml --renderer=asciidoctor --source-path=../../api --output-path=CRD-docs-for-docs-repo.adoc
