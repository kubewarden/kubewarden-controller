build: policy.wasm

policy.wasm: policy.rego
	opa build -t wasm -e policy/main policy.rego utility.rego -o policy.tar.gz
	tar -xf policy.tar.gz /policy.wasm

clean:
	rm -rf *.wasm *.tar.gz
