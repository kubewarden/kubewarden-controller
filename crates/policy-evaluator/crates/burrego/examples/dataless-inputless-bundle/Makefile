build: accept.wasm reject.wasm

accept.wasm: accept.rego
	opa build -t wasm -e policy/main accept.rego -o accept.tar.gz
	tar -xf accept.tar.gz /policy.wasm
	mv policy.wasm accept.wasm

reject.wasm: reject.rego
	opa build -t wasm -e policy/main reject.rego -o reject.tar.gz
	tar -xf reject.tar.gz /policy.wasm
	mv policy.wasm reject.wasm

clean:
	rm -rf *.wasm *.tar.gz
