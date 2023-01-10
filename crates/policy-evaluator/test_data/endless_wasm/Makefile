wasm_endless_loop.wasm: wasm_endless_loop.wat
	wat2wasm wasm_endless_loop.wat -o wasm_endless_loop.wasm

wapc_endless_loop.wasm: wapc_endless_loop.wat
	wat2wasm wapc_endless_loop.wat -o wapc_endless_loop.wasm

.PHONY: build
build: wasm_endless_loop.wasm wapc_endless_loop.wasm

.PHONY: clean
clean:
	rm -rf *.wasm
