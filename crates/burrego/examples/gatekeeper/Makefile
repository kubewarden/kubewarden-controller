SOURCES=$(shell find . -name "*.rego")
OBJECTS=$(SOURCES:%.rego=%.wasm)

all: $(OBJECTS)

%.wasm: %.rego
	opa build --v0-compatible -t wasm -e policy/violation -o $*.tar.gz $<
	tar -xf $*.tar.gz --transform "s|policy.wasm|$*.wasm|" /policy.wasm
	rm $*.tar.gz

clean:
	rm -f *.wasm *.tar.gz
