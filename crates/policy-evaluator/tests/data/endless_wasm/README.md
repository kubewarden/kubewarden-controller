This directory contains the source code of two WebAssembly modules, bot of them
perform an endless loop.

The code is written using the WebAssembly text format (aka `WAT`).

## `wasm_endless_loop.wat`

This is a module meant to be used with vanilla wasmtime engine.

The code exports a function called `endless_loop` that just performs
and endless loop.
This function takes zero parameters and doesn't return anything.

The `start` function of the WebAssembly module invokes the `endless_loop`, that
means that running the final `.wasm` file via something like `wasmtime run` will
cause the endless function to be executed.

## `wapc_endless_loop.wat`

This is a module meant to be used by a waPC host.

This code cheats a little, from the outside it looks like any regular waPC module
because it exposes the two functions required by a waPC host. However, these
two functions are reduced to the bare mimimum.

The most important difference is that no waPC function is registered by the
module. Calling any kind of waPC function from the host will result in an
endless loop being executed.
