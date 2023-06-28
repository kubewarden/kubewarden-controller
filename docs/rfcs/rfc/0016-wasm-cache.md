|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | WASM cache                       |
| Start Date   | Jun 28 2023                      |
| Category     | [Category]                       |
| RFC PR       | [fill this in after opening PR]  |
| State        | **ACCEPTED**                         |


# Summary
[summary]: #summary

This RFC aims to provide a way to reduce the startup time of Policy Server.

# Motivation
[motivation]: #motivation

Policy Server is restarted every time its configuration changes. This includes
changes done to the policies that are deployed through it. This includes adding
or removing policies, plus any kind of change done to an already deployed one
(like a different configuration value, or a version bump).

During the startup Policy Server performs these time expensive operations:

* Download all the policies
* Optimize the WASM code for execution

These operations are repeated every time, because each the state of each Policy
Server instance is not preserved across restarts.

The purpose of this RFC is to find a way to reduce the startup time of
Policy Server so that Kubewarden becomes more reactive to the changes done
to the cluster policies.


## Examples / User Stories
[examples]: #examples

> As a Kubernetes administrator using Kubewarden,
> I want to see the new policy to be enforced
> as soon as possible,
> regardless of the number of policies I have already deployed.

> As a Kubernetes administrator using Kubewarden,
> I want to see the configuration changes done to one of my policies
> to be propagated as soon as possible,
> regardless of the number of policies I have already deployed.

# Detailed design
[design]: #detailed-design

The most expensive operation done by Policy Server at startup is the optimization
of all the WASM modules it has to run. The code has already been optimized to
perform this work in parallel, hence we don't think we could have other gains
by revisiting the startup process.

Moreover, the time spent downloading the policies is significantly shorter than
the time spent optimizing them.

This is because the typical policies are small (~ 3.5 Mb) and, in some environments,
are even mirrored on a local OCI registry that provides fast access to them.

Hence, the idea behind this RFC is to cache the results of WASM optimization
and reuse them.

## Determine if a WASM module didn't change

A WASM module can be reused if its contents didn't change. This can be determined
by comparing the digest of the module. This is available via the OCI manifest.

The SHA256 digest of a WASM module composing a Kubewarden policy can be obtained
in this way:

```console
$ crane manifest ghcr.io/kubewarden/policies/capabilities-psp:v0.1.9 | jq '.layers[0].digest'
"sha256:001d7dc5dd34074429ff013e38b48d9203bf3edeeac7ba2c18323bb14db56851"
```

If the module didn't change, we can attempt to reuse a previously optimized
version of it.

## How WASM module optimization works

In our case, the module optimization is done using
[`wasmtime::Module::precompile_module`](https://docs.rs/wasmtime/10.0.1/wasmtime/struct.Engine.html#method.precompile_module).

Quoting the documentation:

> This method may be used to compile a module for use with a different target host.
> The output of this method may be used with `Module::deserialize` on hosts compatible with the `Config` associated with this `Engine`.
>
> The output of this method is safe to send to another host machine for later execution.
> As the output is already a compiled module, translation and code generation will be skipped and this will improve the performance of constructing a `Module` from the output of this method.

Attempting to load an incompatible module will result in an error as
stated by the [`wasmtime::Module::deserialize`](https://docs.rs/wasmtime/10.0.1/wasmtime/struct.Module.html#method.deserialize)
documentation:

> Note that this function is designed to be safe receiving output from any compiled version of wasmtime itself.
> This means that it is safe to feed output from older versions of Wasmtime into this function, in addition to
> newer versions of wasmtime (from the future!).
> These inputs will deterministically and safely produce an `Err`. This function
> only successfully accepts inputs from the same version of wasmtime, but the safety
> guarantee only applies to externally-defined blobs of bytes, not those defined by any version of wasmtime.
> (this means that if you cache blobs across versions of wasmtime you can be safely guaranteed that future versions of wasmtime will reject old cache entries).

We can keep a cache of the previously optimized modules and attempt to reuse them.
An incompatible module would produce an error, from which we can recover by doing
the optimization again.

It's also possible to determine if the optimized module can be reused without
even attempting to load it. This can be done by using the
[`wasmtime::Engine::precompile_compatibility_hash`](https://docs.rs/wasmtime/10.0.1/wasmtime/struct.Engine.html#method.precompile_compatibility_hash)
function:

> Returns a `std::hash::Hash` that can be used to check precompiled WebAssembly compatibility.
>
> [...] If this `Hash` matches between two `Engine`s then binaries from one are guaranteed to deserialize in the other.

When optimizing an WASM module, we could also store the hash of the `Engine` that
produced it.

Later, we can use this hash to quickly find a pre-optimized WASM module that we
could reuse.

## Where to store the pre-optimized modules

We could store the pre-optimized modules inside of an OCI registry.
The Kubewarden helm chart could, when enabled via a dedicated toogle
option, deploy an internal OCI registry.

At startup time, Policy Server would query the internal registry looking for
a pre-built WASM module. When the module is found, the Policy Server
could download it and consume that.

When not found, the Policy Server would download the vanilla WASM module, optimize
it and then, before starting to listen for incoming requests, push the pre-built
module to the OCI registry.

Multiple Policy Server instances could be optimizing and pushing the same WASM
module at the same time. However, the OCI registry can handle these concurrent
push requests.

## The caching OCI registry

The OCI registry used for caching would not be exposed outside of the cluster.
It would need to be secured with https and HTTP basic auth.

The auth credentials need to be stored inside of a Kubernetes Secret that would
be mounted inside of the Policy Server instances. In this way, we would be able
to guarantee that only trusted actors could read and write to this cache registry.

In terms of storage, the registry could either use a Persistent Volume or
just use an `emptyDir`. This should be tunable via the helm chart of Kubewarden.

When an `emptyDir` volume is used, all the cached data would be lost whenever the
Pod running the registry is restarted. However, being that a cache, this should
not be a problem; the Policy Server would re-optimize the policies at its next
startup, resulting in a cold start.

# Drawbacks
[drawbacks]: #drawbacks

This introduces a new component being deployed on the cluster: the OCI registry
used as cache.

# Alternatives
[alternatives]: #alternatives

## Use a Persistent Volume

Right now each `PolicyServer` CR is implemented by using a `Deployment`. The
Deployment usually has a replica size of 2, but this detail can be changed by
the user.
All the `Pod`s that are part of the `Deployment` are storing their data inside
of a temporary directory. The contents of this directory are lost whenever
the Pod is restarted (like during a Deployment rollout).

We could change the `Deployment` template to ensure all its Pods have access
to a Persistent Volume. We could then use this PV to store both vanilla and
the optimized WASM modules.

In this scenario, we would have to find a way to ensure only one Pod has
exclusive access to the directory where the vanilla and the optimized WASM
files are going to be written.

This could be done using a file lock. However, file locks do not work in
a consistent way across different network file systems. This could lead to
some race conditions happening with certain combinations of PV drivers.
We fear that using a file lock would cause a higher maintenance.

Another possibility is to use a Kubernetes primitive called
[`Lease`](https://kubernetes.io/docs/concepts/architecture/leases/) to ensure
that only one of the Pods (the leader) has write access to the PV.

### Leverage the `ReadWriteOncePod` access mode

Another variation on this theme could leverage the
new [`ReadWriteOncePod` access mode](https://kubernetes.io/blog/2023/04/20/read-write-once-pod-access-mode-beta/).

This feature just gratuated beta as part of the Kubernetes 1.27 release.
This access mode can be only used by PV is provided by a
[CSI driver](https://kubernetes-csi.github.io/docs/drivers.html);
moreover the CSI driver must be offer this access mode.

I think we should not investigate the usage of this access mode because
we would greatly limit the availability of the WASM caching feature.

## Use Stateful Set

We could deploy PolicyServer via a Stateful set. This would allow each Pod to
have a dedicated PV. This PV could then be used by the Pod to store both the
vanilla and the optimized WASM files.

The only disadvantage of this solution is that no sharing is done among the
Pods that are part of the Stateful set. Which means, the same download & optimization
task is going to be done multiple times, one per Pod.


# Unresolved questions
[unresolved]: #unresolved-questions

I think we should look more into the other alternatives, these are probably less
intrusive compared to the adoption of an OCI registry. That's because they built
on top of Kubernetes primitives and would require less work to be done (the Stateful
set option would theoretically require no work on Policy Server).
