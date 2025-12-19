SOURCES=$(shell find . -name "*.rego")
OBJECTS=$(SOURCES:%.rego=%.wasm)

all: $(OBJECTS)

%.wasm: %.rego
	opa build -t wasm -e policy/main utility/policy.rego -o $*.tar.gz $<
	tar -xf $*.tar.gz --transform "s|policy.wasm|$*.wasm|" /policy.wasm
	rm $*.tar.gz

clean:
	rm -f *.wasm *.tar.gz
