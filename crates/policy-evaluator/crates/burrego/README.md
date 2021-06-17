# Burrego

**⚠️  experimental ⚠️**

> A Rust tortilla wrapped around a Rego Wasm filling 🌯🌯🌯 🤤 😋

Burrego can load [Open Policy Agent](https://www.openpolicyagent.org/docs/)
policies built into [WebAssembly](https://webassembly.org/)
and evaluate them.

OPA policies can be compiled to WebAssembly module (aka Wasm) using the
`opa` command-line tool.

Read [here](https://www.openpolicyagent.org/docs/latest/wasm/) for more
information about OPA and WebAssembly.

[![demo](/demo.gif)](https://asciinema.org/a/420933)

## Usage

A policy can be evaluated in this way:

```
$ burrego eval -i <input data> -d <data> rego-policy.wasm
```

For example:

```console
$ burrego eval \
          -i '{"message": "world"}' \
          -d '{"world": "world"}' \
          examples/example-with-data/policy.wasm
[
  {
    "result": true
  }
]
```

More examples can be found [here](/examples/README.md).

## Installation

burrego can be built from sources using:

```
cargo install --git https://github.com/flavio/burrego.git --branch main
```

Pre-built Linux binaries can be found [here](https://github.com/flavio/burrego/releases).

## Limitations

The OPA provides a series of that can be used by policy authors.

Some of these built-ins are automatically "bundled" with the final
Wasm file, others have to be provided by the WebAssembly execution host
(burrego in this case).

[This](https://www.openpolicyagent.org/docs/latest/policy-reference/#built-in-functions)
page provides a list of all the built-ins offered by OPA. The *"Wasm support"*
column clearly states which ones are automatically provided (✅) and which are
instead *"SDK-dependent"*.

burrego currently doesn't support all the OPA built-ins. It will refuse to
evaluate a policy that requires an unsupported built-in.

Execute this command to get a list of the supported built-ins:

```console
$ burrego builtins
```

## Acknowledgement

burrego is built with Rust, using the [wasmtime](https://github.com/bytecodealliance/wasmtime)
WebAssembly runtime.

The code performing the OPA Wasm evaluation has been implemented using the
[OPA spec](https://www.openpolicyagent.org/docs/latest/wasm/)
and porting portions of
[npm-opa-wasm](https://github.com/open-policy-agent/npm-opa-wasm/) to Rust.
