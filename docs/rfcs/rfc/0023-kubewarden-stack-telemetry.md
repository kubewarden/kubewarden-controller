|              |                                           |
| :----------- | :---------------------------------------- |
| Feature Name | Kubewarden environment telemetry          |
| Start Date   | 2025-08-28                                |
| Category     | telemetry                                 |
| RFC PR       | https://github.com/kubewarden/rfc/pull/51 |
| State        | **IN-REVIEW**                             |

# Summary

This RFC describes how the Kubewarden stack will send telemetry data about the
environment in which it is running. The goal isn't to collect information
about user applications, but rather to learn more about typical Kubewarden deployment
environments. This data will help guide the
project's future development.

Kubewarden stack telemetry will be enabled by default, but users will have an
easy way to disable it.

# Motivation

The Kubewarden team currently has limited visibility into the environments
where users deploy the project. This information is invaluable for making
data-driven decisions about the project's future. For this reason, we would
like to add a feature to the Kubewarden stack that allows sending
non-sensitive, anonymous environment information to a central service for
aggregation and analysis.

## Examples / User Stories

As the Kubewarden team, I want to know how many PolicyServers and policies are
typically deployed in an instance.

As the Kubewarden team, I want to know how many policies a PolicyServer usually
serves.

As the Kubewarden team, I want to know which Kubewarden versions are in use.

As the Kubewarden team, I want to know the most common Kubernetes versions used
with Kubewarden.

As a Kubewarden user, I want to help improve the project by providing anonymous
usage data without compromising my privacy or violating data protection
regulations.

As a Kubewarden user, I want to ensure that sending telemetry data does not
introduce a significant security vulnerability into my environment.

As a Kubewarden user, I want to ensure that the process of sending telemetry
data does not consume excessive resources in my environment.

As a Kubewarden user, I want an easy way to disable the Kubewarden environment
telemetry data sending

As a Kubewarden user, I want to receive warning in the logs about available
upgrades

# Detailed design

> [!WARNING]
> As a CNCF project, it's necessary to get approval from the CNCF to implement either of the following options.
> [Telemetry Data Collection and Usage Policy | Linux Foundation](https://www.linuxfoundation.org/legal/telemetry-data-policy)

This feature involves creating a dedicated controller reconciler
that sends telemetry data to a remote server. It requires changes in some
Kubewarden components, as described below.

## Desired metrics

The changes described in this document aim to allow the Kubewarden team to
gather the following metrics:

- Number of active PolicyServers.
- Number of active policies.
- Average number of policies per PolicyServer.
- Number of Kubewarden installations by version.
- Number of Kubewarden installations by Kubernetes version.
- Official policies from the Kubewarden project in use.

## Controller Changes

To send information about the environment, the controller would be responsible
for collecting and transmitting the data to a remote, central place. The
controller already has access to all Kubewarden resources and can be granted
permissions to access other relevant information.

The main changes to the Kubewarden controller would be:

- A configuration option to specify the endpoint that receives the
  information.
- A periodic job within the controller to collect and send the information.

### Controller Configuration

The controller should have two new CLI flags to enable telemetry collection and
delivery: `--stack-telemetry-endpoint` and `--stack-telemetry-period`. The former
contains the full URL of the remote server. The latter defines the interval at
which the controller sends data, defaulting to `1h`. For example:

```
manager --leader-elect ... --stack-telemetry-endpoint="https://metrics.kubewarden.io/" --stack-telemetry-period=6h ...
```

When the `--stack-telemetry-endpoint` flag isn't defined, no telemetry will be
sent. The feature will be disabled by default.

### Controller Information Collection and Delivery

When configuring the telemetry endpoint, a new periodic job should be created
in the controller to collect and send the data. This job can be implemented
using the Runnable interface from the controller-runtime package and integrated
into the manager alongside the existing reconcilers.

This new periodic reconciler will start a `time.Ticker` that will periodically:

- Collect information about how many PolicyServers are deployed.
- Collect information about how many policies are deployed.
- Collect all required relevant information desired to the metrics.
- Collect the Kubewarden version in use (this can be a constant updated on
  every release).
- Collect the Kubernetes version.
- Build a JSON payload with the collected data and send it to the remote server
  using secure communication.
- The controller logs the available updates for the Kubewarden version running returned by
  the [upgrade-responder](https://github.com/longhorn/upgrade-responder) server.

> [!NOTE]
> The information collected by the reconciler may change over time
> considering the needs for the desired metrics.

The execution of this new reconciler should never interrupt the functionality
of the remaining reconcilers. This means that if the controller is
misconfigured with invalid endpoint, the reconciler should log an error and
continue.

## Helm Chart Changes

The Kubewarden Helm charts would require new values to configure the
controller's CLI flags.

```yaml
stackTelemetry:
  enabled: true
  endpoint: "https://metrics.kubewarden.io"
  period: "1h"
```

When `stackTelemetry.enabled` is `true`, the feature is enabled in the
controller via the corresponding CLI flags.

The `stackTelemetry.enabled` setting will be `true` by default. Users will be
notified during the Kubewarden stack install and upgrade via Helm NOTES.txt
that this telemetry is included, and instructions to disable it will be
provided

## Telemetry Server

The telemetry server will be an instance of the [Longhorn
upgrade-responder](https://github.com/longhorn/upgrade-responder).
This server receives information from controllers and store it in an
InfluxDB database for further analysis.

The server exposes an endpoint to receive a JSON payload with the following
structure:

```json
{
  "appVersion": "v1.28.0",
  "extraTagInfo": {
    "kubernetesVersion": "v1.33.0"
  },
  "extraFieldInfo": {
    "policyServerCount": 2,
    "policiesCount": 3,
    "namespaceUid": "<namespace-uid-where-kubewarden-is-installed>"
  }
}
```

When the `upgrade-responder` receives a request, it will:

1. Validate the payload using a predefined JSON schema.
2. [Infer](https://github.com/longhorn/upgrade-responder/blob/a6f6c7736b7e420b07ae7d813765dac778ebc638/upgraderesponder/service.go#L509)
   the origin's geo-location from the request's source IP address.
3. Store the enriched data in an InfluxDB database.
4. Respond the request with the available updates to the given Kubewarden version
   defined in the `appVersion` field.

The `upgrade-responder` will write the request data into an InfluxDB metric. The
`extraTagInfo` values will be added as
[tags](https://github.com/longhorn/upgrade-responder/blob/a6f6c7736b7e420b07ae7d813765dac778ebc638/upgraderesponder/service.go#L538),
while the `extraFieldInfo` values will be added as
[fields](https://github.com/longhorn/upgrade-responder/blob/a6f6c7736b7e420b07ae7d813765dac778ebc638/upgraderesponder/service.go#L558).

For example, the JSON payload above would result in a data point with the
following tags:

- `appVersion`: The Kubewarden version (e.g., v1.28.0).
- `kubernetesVersion`: The Kubernetes version where the controller is running
  (e.g., v1.33.0).
- `city`: City name extracted from the request's source IP.
- `country`: Country name extracted from the request's source IP.
- `country_isocode`: Country ISO code extracted from the request's source IP.

The same data point will have the following fields:

- `policyServerCount`: The number of PolicyServers deployed in the cluster.
- `policiesCount`: The number of policies deployed in the cluster.
- `namespaceUid`: A UID to uniquely identify the Kubewarden stack installation.
  This should be UID of the Kubewarden installation namespace.
- `value`: A
  [field](https://github.com/longhorn/upgrade-responder/blob/a6f6c7736b7e420b07ae7d813765dac778ebc638/upgraderesponder/service.go#L49C36-L49C95)
  always set to `1`,
  [added](https://github.com/longhorn/upgrade-responder/blob/a6f6c7736b7e420b07ae7d813765dac778ebc638/upgraderesponder/service.go#L560)
  automatically by `upgrade-responder`. This default value ensures that the data
  point has a value for metric calculations, even if the request contains no
  other fields. In other words, it's a dummy InfluxDB field used to count the
  number of data points

  ### Request validation schema

  The `upgrade-responder` should be configured with a JSON schema used to validate the
  request payload. This is a proposed validation schema to be used:

  ```json
  {
    "appVersionSchema": {
      "dataType": "string",
      "maxLen": 200
    },
    "extraTagInfoSchema": {
      "kubernetesVersion": {
        "dataType": "string",
        "maxLen": 200
    },
    "extraFieldInfoSchema": {
      "policyServerCount": {
        "dataType": "float"
      },
      "policiesCount": {
        "dataType": "float"
      },
      "namespaceUid": {
        "dataType": "string",
        "maxLen": 200
    }
  }
  ```

### Understanding Tags and Fields

There are differences from InfluxDB `tags` and `fields` which may be relevant
to document here as well. Tags are indexed metadata which can be used to group
and filter data points. While `fields` are the actual metric data.

| Aspect          | Tags                                                                                | Fields                                                                |
| :-------------- | :---------------------------------------------------------------------------------- | :-------------------------------------------------------------------- |
| **Purpose**     | Serve as indexed metadata used for filtering and grouping (e.g., `host`, `region`). | Hold the actual measured values (e.g., `temperature`, `cpu_usage`).   |
| **Indexing**    | Stored in an inverted index; queries on tags are very fast.                         | Not indexed; queries must scan data, which can be slower.             |
| **Cardinality** | High cardinality (many unique values) can degrade database performance.             | Low impact on performance; many distinct field values are acceptable. |
| **Data Types**  | Limited to strings.                                                                 | Support numeric types, booleans, and strings.                         |

### Grafana Dashboard

Alongside the `upgrade-responder` and InfluxDB, a Grafana instance with a custom
dashboard will be configured. The dashboard will use InfluxDB as its data
source and provide queries to visualize the desired metrics.

### Telemetry Server Infrastructure

The `upgrade-responder`, InfluxDB, and Grafana instances used for Kubewarden
telemetry will be maintained by the SUSE team. All Kubewarden maintainers
listed in the maintainers CNCF mail list will have access to the collected
data.

# Drawbacks

- When requiring new metadata or more metric data, code
  changes will be needed. Along with a new release for both the controller and, possibly, the telemetry
  server. The JSON schema versions must be kept synchronized.

# Alternatives

The following subsection is an option provided during the writing of this RFC. But, it
was not selected by a majority of the team. The team decided to move forward with the
`upgrade-responder` option because this is a solution used by other CNCF
projects (Longhorn). Also, we (SUSE Rancher — who is willing to pay for the
infrastructure) have experience managing and maintaining the server-side
infrastructure.

## Not selected option: OpenTelemetry Integration

This implementation option aims for a less intrusive approach, decoupling the
controller from the telemetry back-end. With this design, all telemetry will be
managed outside the Kubewarden controller's reconciliation loop. The controller
will be instrumented with telemetry collection points that send data to an
OpenTelemetry collector, which will be configured to forward this data to
a remote location.

This option is inspired by previous observability work done in collaboration
with SUSE.

### Controller Changes

The controller's `kubewarden-controller/internal/metrics`
[package](https://github.com/kubewarden/kubewarden-controller/blob/main/internal/metrics/metrics.go)
can be extended by adding new metrics to track the number of PolicyServers and
policies deployed over time. These new metrics should also contain information
about the Kubewarden and Kubernetes versions in use.

The new metric can create time series for each policy like this, using the
time-series database to group similar series:

```go
policiesGauge, err := meter.Int64Gauge("deployed-policies", metric.WithDescription("The number of deployed policies"))
if err != nil {
    log.Fatal(err)
}
// Attributes represent additional key-value descriptors that can be bound
// to a metric observer or recorder.
commonAttrs := []attribute.KeyValue{
    attribute.String("policy_server_id", policy.GetPolicyServer().GetUID()),
    attribute.String("policy_server_image", policy.GetPolicyServer().GetImageDigest()),
    attribute.String("module", policy.GetModuleDigest()),
    attribute.String("kubewarden_version", KUBEWARDEN_VERSION),
    attribute.String("instance_uid", getInstanceUID()), // Corrected key name for consistency
}

policiesGauge.Record(context.Background(), 1, metric.WithAttributes(commonAttrs...)) // Corrected context.Background()
```

Once the metric is recorded, it's up to the OpenTelemetry collector to
manipulate the data and send it to a remote location, which can be another
OpenTelemetry collector or a time-series database (e.g., Prometheus).

### OpenTelemetry Configuration

In the OpenTelemetry collector configuration, a new pipeline will be added to
redirect the new controller metric to a remote location for further analysis.
This is an example of an initial configuration used to forward the metric to a
remote OpenTelemetry collector.

```yaml
receivers:
  otlp:
    protocols:
      grpc: {}
processors:
  # Control how much time we can wait before sending the metric to the remote Otel collector
  batch:
    timeout: 1h
  # Drop any metrics not called "deployed-policies"
  filter/dropInternalMetrics:
    error_mode: ignore
    metrics:
      metric:
        - 'name != "deployed-policies"' # metrics not called deployed-policies will be dropped
  attributes:
    - key: kubewarden_version
      action: upsert
      value: v1.28.0 # this value can be defined in the Helm chart installation
    # Note: The Kubernetes version can often be populated automatically by an Otel resource detector.
    - key: kubernetes_version
      action: upsert
      value: v1.33.0
exporters:
  otlphttp/remoteKubewardenOtel:
    auth:
      authenticator: bearertokenauth
    endpoint: https://metric.kubewarden.io
service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [attributes, filter/dropInternalMetrics, batch]
      exporters: [otlphttp/remoteKubewardenOtel] # Corrected to match exporter name
```

This OpenTelemetry configuration can be used to control the telemetry export
and, be expanded over time to include more metadata by leveraging the rich
ecosystem of OpenTelemetry
[processors](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor).
This would potentially need no changes to the controller code. This makes telemetry
customization more flexible. In the example above, processors will be used to add
labels, filter unrelated metrics, and batch metrics before sending.

All OpenTelemetry collector configuration can be managed in the Helm chart
installation/update. The remote endpoint would be provided in the Helm Chart
values. If the `stackTelemetry.enabled` is disabled, the OpenTelemetry
configuration won't be applied:

```yaml
stackTelemetry:
  enabled: true
  remoteOtelEndpoint: "https://metrics.kubewarden.io"
  batchTimeout: "1h"
```

The remote OpenTelemetry collector's configuration is abstracted from the user.
For instance, it could use the [GeoIP
Processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/geoipprocessor)
to add location information to the received metrics.

# Unresolved questions

# Reference

[metric package - go.opentelemetry.io/otel/metric - Go Packages](https://pkg.go.dev/go.opentelemetry.io/otel/metric#Int64Gauge)

[go.opentelemetry.io/otel/attribute](https://pkg.go.dev/go.opentelemetry.io/otel/attribute)

[opentelemetry-collector-contrib/processor/filterprocessor/README.md at main · open-telemetry/opentelemetry-collector-contrib · GitHub](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/filterprocessor/README.md)

[opentelemetry-collector-contrib/processor/geoipprocessor at main · open-telemetry/opentelemetry-collector-contrib · GitHub](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/geoipprocessor)

[opentelemetry-collector-contrib/processor at main · open-telemetry/opentelemetry-collector-contrib · GitHub](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor)

[opentelemetry-collector/processor at main · open-telemetry/opentelemetry-collector · GitHub](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor)

https://github.com/longhorn/upgrade-responder
