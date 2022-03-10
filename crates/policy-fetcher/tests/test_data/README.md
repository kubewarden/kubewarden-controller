Fixtures used inside of unit tests.

## `simple.wasm`

This is the simplest Wasm module that can be produced while still being compliant
with the official spec.

This is produced by the creating a file named `simple.wat` with the following contents:

```
(module)
```

and then invoke:

```console
wat2wasm simple.wat
```
