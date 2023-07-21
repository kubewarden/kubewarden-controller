|              |                                                   |
| :----------- | :------------------------------------------------ |
| Feature Name | Policy Server: reuse optimized Wasm modules       |
| Start Date   | Jul 18 2023                                       |
| Category     | [Category]                                        |
| RFC PR       | [PR22](https://github.com/kubewarden/rfc/pull/22) |
| State        | **ACCEPTED**                                      |


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
* Optimize the Wasm code for execution

These operations are repeated every time, because the state of each Policy
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
of all the Wasm modules it has to run. The code has already been optimized to
perform this work in parallel, hence we don't think we could have other gains
by revisiting the startup process.

Moreover, the time spent downloading the policies is significantly shorter than
the time spent optimizing them.

This is because the typical policies are small (~ 3.5 Mb) and, in some environments,
are even mirrored on a local OCI registry that provides fast access to them.

Hence, the idea behind this RFC is to cache the results of Wasm optimization
and reuse them.

## Determine if a WASM module didn't change

A Wasm module can be reused if its contents didn't change. This can be determined
by comparing the digest of the module. This is available via the OCI manifest.

The SHA256 digest of a Wasm module composing a Kubewarden policy can be obtained
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

When optimizing an Wasm module, we could also store the hash of the `Engine` that
produced it.

Later, we can use this hash to quickly find a pre-optimized Wasm module that we
could reuse.

## Where to store the pre-optimized modules

Right now each `PolicyServer` CR is implemented by using a `Deployment`. The
Deployment usually has a replica size of 2, but this detail can be changed by
the user.
All the `Pod`s that are part of the `Deployment` are storing their data inside
of a temporary directory. The contents of this directory are lost whenever
the Pod is restarted (like during a Deployment rollout).

We could change the `Deployment` template to ensure all its Pods have access
to a Persistent Volume. We could then use this PV to store both vanilla and
the optimized Wasm modules.

In this scenario, we have to find a way to ensure only one Pod has
exclusive write access to the directory where the vanilla and the optimized Wasm
files are going to be written.

This could be done using a file lock. However, file locks do not work in
a consistent way across different network file systems. This could lead to
some race conditions happening with certain combinations of PV drivers.
We fear that using a file lock would cause a higher maintenance.

Another possibility is to use a Kubernetes primitive called
[`Lease`](https://kubernetes.io/docs/concepts/architecture/leases/) to ensure
that only one of the Pods (the leader) has write access to the PV.

## Using Kubernetes `Lease`

The `Lease` resource is a primitive leveraged by Kubernetes controllers to build
a lock system that is then used for the leader election process.

The hard job of building a lock system is done on the client side. For example,
the Kubernetes Go client does that inside of the
[`k8s.io/client-go/tools/leaderelection/resourcelock`](https://pkg.go.dev/k8s.io/client-go@v0.27.3/tools/leaderelection/resourcelock)
package.
In the rust ecosystem this functionality is provided by the [kubert](https://crates.io/crates/kubert)
crate. This crate is also used by one of [linkerd controllers](https://github.com/linkerd/linkerd2/tree/main/policy-controller).

We can rely on [`kubert::lease::LeaseManager`](https://docs.rs/kubert/0.16.1/kubert/lease/struct.LeaseManager.html)
to ensure exclusive write access to this shared Persistent Volume.

## New deployment model

Policy Server would continue to be deployed using a Deployment object.
A new Persistent Volume would then be defined. This is where all the `.wasm`
files and all their optimized versions would be saved.

The deployment would then define a new init container. The Policy Server
configuration would be injected into the init container as a read-only file.
The container would also have write access to the Persistent Volume described
above.

The init container would then run a program that performs the following steps:

1. Obtain ownership of a lock backed by a Kubernetes Lease resource.
2. Wait until exclusive ownership is obtained.
3. Inspect the configuration of Policy Server, download all the missing `.wasm`
  modules
4. For each downloaded `.wasm` module, look for an optimized version of it inside
  of the Persistent Volume
5. If no optimized version is found, or if the found one is not compatible with
  the current wasmtime engine, generate a new one and write it to disk
6. Once all the modules have been downloaded and optimized exit

The typical Policy Server deployment is made by two Pods. In this case, one Pod
will obtain the exclusive access to the shared lock. Its init container will
eventually update the contents of the Persistent Volume and then it will start.
The other Pod will be initially "stuck" with its init container waiting to acquire
the shared lock. Once the lock is owned, the init container program will exit
almost immediately, given all the modules and their optimized versions are
already inside of the Persistent Volume.

The usage of an init container has the following benefits:

* Create a clear representation of the bootstrap process of the Policy Server
  Pod
* Avoid further complexity to be added to the Policy Server codebase

The "download & optimize" code would be provided by a dedicated binary.
To keep things simple, this binary can be stored inside of the already existing
Policy Server container image. By doing that we do not complicate our build pipeline
and we do not introduce a new container image that has to be mirrored when
the Kubewarden stack is deployed inside of an air-gapped environment.

# Drawbacks
[drawbacks]: #drawbacks

## Usage of a Persistent Volume

A Persistent Volume must be created. Our helm chart should not create the Persistent
Volume, but rather rely on a [Storage Class](https://kubernetes.io/docs/concepts/storage/storage-classes/)
to have that created.

Development/testing environments should not be affected by that because
k3s, minikube, kind and other similar projects provide a default Storage Class
that is ready to be used.

The majority of production environments already feature a Storage Class that
can be reused.

We can also change the helm chart to handle these possible configurations:

* Use the default Storage Class
* Use a Storage Class specified by the user
* Do not use a Storage Class, use a Persistent Volume already defined by the
  cluster administrator

## Rust and Kubernetes Lease handling

The complexity of building a lock system using the Kubernetes Lease resource is
entirely inside of the Kubernetes client being used.

In the Rust ecosystem the `kubert` crate provides this functionality. Despite being
used by linkerd, the crate development/maintenance seems to be low.

We can reduce the impact of this dependency by creating a dedicated program that
performs the download and optimization task. If `kubert` is abandoned we
can write a Go program that takes the lock and then `exec` the "download & optimize"
Rust code (which would no longer handle the lock aspects).

## Garbage collector

Not really a drawback, but something to keep in mind. Over the time the size of
the Persistent Volume will grow. We will have to introduce a way to ensure old
modules (and their optimized counterparts) are removed when no longer needed.

# Alternatives
[alternatives]: #alternatives

## Use a OCI registry to cache data

Instead of using a Persistent Volume, we could push all the optimized modules
inside of a dedicated OCI registry.

This approach has been described inside of
[this RFC](https://github.com/kubewarden/rfc/blob/main/rfc/0016-wasm-cache.md),
which has been
rejected because of its complexity.

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

None
