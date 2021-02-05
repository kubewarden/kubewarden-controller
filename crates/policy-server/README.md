> **Note well:** don't forget to checkout [Chimera's documentation](https://chimera-kube.github.io/chimera-book/)
> for more information

# policy-server

`policy-server` is a
[Kubernetes dynamic admission controller](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
that uses Chimera Policies to validate admission requests.

Chimera Policies are simple [WebAssembly](https://webassembly.org/)
modules.

# Deployment

We recommend to rely on the [chimera-controller](https://github.com/chimera-kube/chimera-controller)
and the [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
provided by it to deploy the Chimera stack.

## Configuring policies

A single instance of `policy-server` can load multiple Chimera policies. The list
of policies to load, how to expose them and their runtime settings are handled
through a policies file.

By default `policy-server` will load the `policies.yml` file, unless the user
provides a different value via the `--policies` flag.

This is an example of the policies file:

```yml
dedicated_nodes_tenant_A:
  url: registry://ghcr.io/chimera-kube/policies/pod-toleration:v0.0.2
  settings:
    taint_key: dedicated
    taint_value: tenantA
    allowed_groups:
      - administrators
      - tenant-a-users
dedicated_nodes_tenant_B:
  url: registry://ghcr.io/chimera-kube/policies/pod-toleration:v0.0.2
  settings:
    taint_key: dedicated
    taint_value: tenantB
    allowed_groups:
      - administrators
      - tenant-b-users
namespace_simple:
  url: file:///tmp/namespace-validate-policy.wasm
  settings:
    valid_namespace: chimera-approved
```

The YAML file contains a dictionary with strings as keys, and policy objects as values.

The key that identifies a policy is used by `policy-server` to expose the policy
through its web interface. Policies are exposed under `/validate/<policy id>.

For example, given the configuration file from above, the following API endpoint
would be created:

  * `/validate/dedicated_nodes_tenant_A`: this exposes the `pod-toleration:v0.0.2`
    policy. The Wasm module is downloaded from the OCI registry of GitHub.
  * `/validate/dedicated_nodes_tenant_B`: this exposes the `pod-toleration:v0.0.2`
    policy. The Wasm module is downloaded from the OCI registry of GitHub.
  * `/validate/namespace_simple`: this exposes the `namespace-validate-policy`
    policy. The Wasm module is loaded from a local file located under `/tmp/namespace-validate-policy.wasm`.

It's common for policies to allow users to tune their behaviour via ad-hoc settings.
These customization parameters are provided via the `settings` dictionary.

For example, given the configuration file from above, the `namespace_simple` policy
will be invoked with the `valid_namespace` parameter set to `chimera-approved`.

Note well: it's possible to expose the same policy multiple times, each time with
a different set of paraments. For example, given the configuration file from above,
this is done by the `dedicated_nodes_tenant_A` and by the `dedicated_nodes_tenant_B` endpoints.

The Wasm file providing the Chimera Policy can be either loaded from
the local filesystem or it can be fetched from a remote location. The behaviour
depends on the URL format provided by the user:

* `file:///some/local/program.wasm`: load the policy from the local filesystem
* `https://some-host.com/some/remote/program.wasm`: download the policy from the
  remote http(s) server
* `registry://localhost:5000/project/artifact:some-version` download the policy
  from a OCI registry. The policy must have been pushed as an OCI artifact


## Building

You can either build `chimera-admission` from sources (see below) or you can
use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/chimera-kube/packages/container/package/policy-server).

The `policy-server` binary can be built in this way:

```shell
$ cargo build
```
