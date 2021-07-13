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
a different set of paraments.

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
levels are availble too.

Policy server can produce logs events using different formats. The `--log-fmt`
flag is used to choose the format to be used.

### Standard output

By default, log messages are printed on the standard output using the
`text` format. Logs can be printed as JSON objects using the `json` format type.

### Jaeger

[Jaeger](https://www.jaegertracing.io/) is an open souce distributed tracing
solution.

Policy server can send trace events directly to a Jaeger collector using the
`--log-fmt jaeger` flag.

Underneat, policy server relies on [Open Telemetry](https://github.com/open-telemetry/opentelemetry-rust)
to send events to the Jaeger collector.

By default, events are sent to a collector listening on localhost. However, 
additional Jaeger settings can be specified via [these environment variables](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/sdk-environment-variables.md#jaeger-exporter):

| Name                            | Description                                                      | Default                                                                                          |
|---------------------------------|------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| OTEL_EXPORTER_JAEGER_AGENT_HOST | Hostname for the Jaeger agent                                    | "localhost"                                                                                      |
| OTEL_EXPORTER_JAEGER_AGENT_PORT | Port for the Jaeger agent                                        | 6832                                                                                             |
| OTEL_EXPORTER_JAEGER_ENDPOINT   | HTTP endpoint for Jaeger traces                                  | <!-- markdown-link-check-disable --> "http://localhost:14250"<!-- markdown-link-check-enable --> |
| OTEL_EXPORTER_JAEGER_TIMEOUT    | Maximum time the Jaeger exporter will wait for each batch export | 10s                                                                                              |
| OTEL_EXPORTER_JAEGER_USER       | Username to be used for HTTP basic authentication                | -                                                                                                |
| OTEL_EXPORTER_JAEGER_PASSWORD   | Password to be used for HTTP basic authentication                | -                                                                                                |

A quick evaluation of Jaeger can be done using its "all-in-one" container
image.

The image can be started via:
```console
docker run -d -p6831:6831/udp -p6832:6832/udp -p16686:16686 -p14268:14268 jaegertracing/all-in-one:latest
```

**Note well:** this Jaeger deployment is not meant for production. Please
take a look at [Jaeger's official documentation](https://www.jaegertracing.io/docs/)
for more details.

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

# Building

You can either build `kubewarden-admission` from sources (see below) or you can
use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/kubewarden/packages/container/package/policy-server).

The `policy-server` binary can be built in this way:

```shell
$ cargo build
```
