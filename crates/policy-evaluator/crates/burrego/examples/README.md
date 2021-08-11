# How to build the policies

```console
opa build -t wasm -e example/hello example-with-data/example.rego
opa build -t wasm -e kubernetes/admission/deny k8s-basic/example.rego
```

> Note well: the entrypoint is really important, a wrong entrypoint will lead
> to a policy that won't evaluate nothing at all.
>
> The entrypoint is expressed in the form of `<package>/<variable>`. In the
> example from above, the package is named `example` and the variable holding
> the result is `hello`.


This will produce a `bundle.tar.gz` file, which contains the `policy.wasm` file
load.

# How to run the policies

## Simple Kubernetes policy

The policy finds the container images that are not coming from the `hooli.com`
container registry.

The policy takes as input a pre-recorded AdmissionReview request, this can be
found inside of the `./k8s-basic/input.json` file.

This evaulation can be done in this way:
```console
$ burrego eval -i $(cat examples/k8s-basic/input.json| jq -c) examples/k8s-basic/policy.wasm
[
  {
    "result": [
      "image 'nginx' comes from untrusted registry",
      "image 'mysql' comes from untrusted registry"
    ]
  }
]
```

> **Note well:** the `jq` tool must be installed to perform the bash one-liner
> from above.

## `example-builtin-provided-by-sdk`

The policy matches when `input.message` equals to `looking for <data.world>`.


This evaulation will produce a match:
```console
$ burrego eval -i '{"message": "looking for world"}' -d '{"world": "world"}' examples/example-builtin-provided-by-sdk/policy.wasm
[
  {
    "result": true
  }
]
```

While this one won't:
```console
$ burrego eval -i '{"message": "foo"}' -d '{"world": "world"}' examples/example-builtin-provided-by-sdk/policy.wasm
[
  {
    "result": false
  }
]
```

## `example-builtin-provided-by-wasm`

The policy matches when `input.message` equals to `UPPERCASE(data.world)`.


This evaulation will produce a match:
```console
$ burrego eval -i '{"message": "WORLD"}' -d '{"world": "world"}' examples/example-builtin-provided-by-wasm/policy.wasm
[
  {
    "result": true
  }
]
```

While this one won't:
```console
$ burrego eval -i '{"message": "world"}' -d '{"world": "world"}' examples/example-builtin-provided-by-wasm/policy.wasm
[
  {
    "result": false
  }
]
```

## `example-with-data`

The policy matches when `input.message` equals to `data.world`.


This evaulation will produce a match:
```console
$ burrego eval -i '{"message": "world"}' -d '{"world": "world"}' examples/example-with-data/policy.wasm
[
  {
    "result": true
  }
]
```

While this one won't:
```console
$ burrego eval -i '{"message": "foo"}' -d '{"world": "world"}' examples/example-with-data/policy.wasm
[
  {
    "result": false
  }
]
```

## `example-without-data`

The policy matches when `input.message` equals to `world`.


This evaulation will produce a match:
```console
$ burrego eval -i '{"message": "world"}' examples/example-without-data/policy.wasm
[
  {
    "result": true
  }
]
```

While this one won't:
```console
$ burrego eval -i '{"message": "foo"}' examples/example-without-data/policy.wasm
[
  {
    "result": false
  }
]
```

