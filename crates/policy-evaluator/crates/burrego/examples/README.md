How to build the policies:

```shell
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
