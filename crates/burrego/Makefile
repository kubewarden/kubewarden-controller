TESTDIRS := $(wildcard test_data/*)
.PHONY: $(TESTDIRS)

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: test
test: fmt lint e2e-tests
	cargo test

.PHONY: unit-tests
unit-tests:
	cargo test --lib

.PHONY: clean
clean:
	cargo clean


.PHONY: e2e-tests
e2e-tests: $(TESTDIRS)
$(TESTDIRS):
	$(MAKE) -C $@
