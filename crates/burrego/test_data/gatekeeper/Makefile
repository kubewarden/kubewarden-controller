test: policy.wasm
	bats e2e.bats

policy.wasm: policy.rego
	opa build --v0-compatible -t wasm -e policy/violation -o policy.tar.gz policy.rego
	tar -xf policy.tar.gz /policy.wasm
	rm policy.tar.gz

clean:
	rm -f *.wasm *.tar.gz
