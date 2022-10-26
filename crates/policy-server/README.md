[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-defaults)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-defaults)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6626/badge)](https://bestpractices.coreinfrastructure.org/projects/6626)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fpolicy-server.svg?type=shield)](https://app.fossa.com/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fpolicy-server?ref=badge_shield)

> **Note well:** don't forget to checkout [Kubewarden's documentation](https://docs.kubewarden.io)
> for more information

# policy-server

`policy-server` is a
[Kubernetes dynamic admission controller](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
that uses Kubewarden Policies to validate admission requests.

Kubewarden Policies are simple [WebAssembly](https://webassembly.org/)
modules.

# Deployment

We recommend to rely on the [kubewarden-controller](https://github.com/kubewarden/kubewarden-controller)
and the [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
provided by it to deploy the Kubewarden stack.

## Configuring policies

A single instance of `policy-server` can load multiple Kubewarden policies. The list
of policies to load, how to expose them and their runtime settings are handled
through a policies file.

By default `policy-server` will load the `policies.yml` file, unless the user
provides a different value via the `--policies` flag.

This is an example of the policies file:

```yml
psp-apparmor:
  url: registry://ghcr.io/kubewarden/policies/psp-apparmor:v0.1.3
psp-capabilities:
  url: registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.3
namespace_simple:
  url: file:///tmp/namespace-validate-policy.wasm
  settings:
    valid_namespace: kubewarden-approved
```

The YAML file contains a dictionary with strings as keys, and policy objects as values.

The key that identifies a policy is used by `policy-server` to expose the policy
through its web interface. Policies are exposed under `/validate/<policy id>.

For example, given the configuration file from above, the following API endpoint
would be created:

  * `/validate/psp-apparmor`: this exposes the `psp-apparmor:v0.1.3`
    policy. The Wasm module is downloaded from the OCI registry of GitHub.
  * `/validate/psp-capabilities`: this exposes the `psp-capabilities:v0.1.3`
    policy. The Wasm module is downloaded from the OCI registry of GitHub.
  * `/validate/namespace_simple`: this exposes the `namespace-validate-policy`
    policy. The Wasm module is loaded from a local file located under `/tmp/namespace-validate-policy.wasm`.

It's common for policies to allow users to tune their behaviour via ad-hoc settings.
These customization parameters are provided via the `settings` dictionary.

For example, given the configuration file from above, the `namespace_simple` policy
will be invoked with the `valid_namespace` parameter set to `kubewarden-approved`.

Note well: it's possible to expose the same policy multiple times, each time with
a different set of parameters.

The Wasm file providing the Kubewarden Policy can be either loaded from
the local filesystem or it can be fetched from a remote location. The behaviour
depends on the URL format provided by the user:

* `file:///some/local/program.wasm`: load the policy from the local filesystem
* `https://some-host.com/some/remote/program.wasm`: download the policy from the
  remote http(s) server
* `registry://localhost:5000/project/artifact:some-version` download the policy
  from a OCI registry. The policy must have been pushed as an OCI artifact

## Logging and distributed tracing

The verbosity of policy-server can be configured via the `--log-level` flag.
The default log level used is `info`, but `trace`, `debug`, `warn` and `error`
levels are available too.

Policy server can produce logs events using different formats. The `--log-fmt`
flag is used to choose the format to be used.

### Standard output

By default, log messages are printed on the standard output using the
`text` format. Logs can be printed as JSON objects using the `json` format type.

### Open Telemetry Collector

The open Telemetry project provides a [collector](https://opentelemetry.io/docs/collector/)
component that can be used to receive, process and export telemetry data
in a vendor agnostic way.

Policy server can send trace events to the Open Telemetry Collector using the
`--log-fmt otlp` flag.

Current limitations:

  * Traces can be sent to the collector only via grpc. The HTTP transport
    layer is not supported.
  * The Open Telemetry Collector must be listening on localhost. When deployed
    on Kubernetes, policy-server must have the Open Telemetry Collector
    running as a sidecar.
  * Policy server doesn't expose any configuration setting for Open Telemetry
    (e.g.: endpoint URL, encryption, authentication,...). All of the tuning
    has to be done on the collector process that runs as a sidecar.

More details about OpenTelemetry and tracing can be found inside of
our [official docs](https://docs.kubewarden.io/operator-manual/tracing/01-quickstart.html).

# Building

You can use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/kubewarden/packages/container/package/policy-server).

Alternatively, the `policy-server` binary can be built in this way:

```shell
$ make build
```

# Software bill of materials

Policy server has its software bill of materials (SBOM) published every release.
It follows the [SPDX](https://spdx.dev/) version 2.2 format and it can be found
together with the signature and certificate used to signed it in the
[release assets](https://github.com/kubewarden/policy-server/releases)

# Security

The Kubewarden team is security conscious. You can find our threat model
assessment, responsible disclosure approach and other related things under the
[*security* section of Kubewarden
docs](https://docs.kubewarden.io/security/intro).
