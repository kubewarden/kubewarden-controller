# List of tips and trick for developers

## Tracing

It's easier to test tracing locally, without having to deploy Policy Server into
kubernetes.

Following this tutorial you will end up with the following setup:

  * policy-server: running locally, uncontainerized
  * OpenTelemetry collector: running locally, inside of a container
  * Jaeger all-in-one: running locally, inside of a container

As a first step, start Jaeger:

```console
docker run --rm \
  --name jaeger \
  -p14250:14250 \
  -p16686:16686 \
  jaegertracing/all-in-one:1.27.0
```

On another console, obtain the IP address of the
Jaeger server:

```console
docker container inspect -f '{{ .NetworkSettings.IPAddress }}' jaeger
```

Edit the `otel-collector-minimal-config.yaml` file, ensure you change the
IP address of the Jaeger endpoint.

Start the OpenTelemetry collector:

```console
docker run --rm \
  -p 4317:4317 \
  -p 8889:8889 \
  -v `pwd`/otel-collector-minimal-config.yaml:/etc/otel/config.yaml:ro \
  otel/opentelemetry-collector:0.36.0 \
    --log-level debug \
    --config /etc/otel/config.yaml
```

Start prometheus, so it can start scraping metrics. By adding the `host.docker.internal`, the
prometheus container will be able to reach the OpenTelemetry collector exposed port in the host, and
scrape that endpoint. Check the `prometheus.yml` configuration for more details.

```console
docker run -d --rm \
  --add-host=host.docker.internal:host-gateway \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus:v2.30.3
```

Now start policy-server:

```console
cargo run --release -- \
  --policies policies.yml \
  --workers 2 \
  --log-fmt otlp \
  --log-level debug \
  --enable-metrics
```

Some notes about this command:
  * We are running policy-server in release mode. That's because wasmtime is
    pretty slow at initializing WASM modules when ran in `debug` mode.
  * You must provide a `policies.yml` file, you can take inspiration from `policies.yml.example`

The Jaeger UI can be accessed by opening [localhost:16686](http://localhost:16686).

You can now use a tool like [Postman](https://www.postman.com/) (BTW, there's a
[flatpak](https://flathub.org/apps/details/com.getpostman.Postman) too) to
send POST requests against Policy Server.

The Policy Server process is listening on `localhost:3000`.

Otherwise, you could use `curl` too:

```console
curl --location --request POST 'localhost:3000/validate/psp-capabilities' \
--header 'Content-Type: application/json' \
--data-raw '{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "1299d386-525b-4032-98ae-1949f69f9cfc",
    "kind": {
        "group": "",
        "version": "v1",
        "kind": "Pod"
    },
    "resource": {
        "group": "",
        "version": "v1",
        "resource": "pods"
    },
    "requestKind": {
        "group": "",
        "version": "v1",
        "kind": "Pod"
    },
    "requestResource": {
        "group": "",
        "version": "v1",
        "resource": "pods"
    },
    "name": "nginx",
    "namespace": "default",
    "operation": "CREATE",
    "userInfo": {
        "username": "kubernetes-admin",
        "groups": [
        "system:masters",
        "system:authenticated"
        ]
    },
    "object": {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {
        "name": "nginx",
        "namespace": "default",
        "uid": "04dc7a5e-e1f1-4e34-8d65-2c9337a43e64",
        "creationTimestamp": "2020-11-12T15:18:36Z",
        "labels": {
            "env": "test"
        },
        "annotations": {
            "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"env\":\"test\"},\"name\":\"nginx\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"nginx\"}],\"tolerations\":[{\"effect\":\"NoSchedule\",\"key\":\"example-key\",\"operator\":\"Exists\"}]}}\n"
        },
        "managedFields": [
            {
            "manager": "kubectl",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2020-11-12T15:18:36Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
                "f:metadata": {
                "f:annotations": {
                    ".": {},
                    "f:kubectl.kubernetes.io/last-applied-configuration": {}
                },
                "f:labels": {
                    ".": {},
                    "f:env": {}
                }
                },
                "f:spec": {
                "f:containers": {
                    "k:{\"name\":\"nginx\"}": {
                    ".": {},
                    "f:image": {},
                    "f:imagePullPolicy": {},
                    "f:name": {},
                    "f:resources": {},
                    "f:terminationMessagePath": {},
                    "f:terminationMessagePolicy": {}
                    }
                },
                "f:dnsPolicy": {},
                "f:enableServiceLinks": {},
                "f:restartPolicy": {},
                "f:schedulerName": {},
                "f:securityContext": {},
                "f:terminationGracePeriodSeconds": {},
                "f:tolerations": {}
                }
            }
            }
        ]
        },
        "spec": {
        "volumes": [
            {
            "name": "default-token-pvpz7",
            "secret": {
                "secretName": "default-token-pvpz7"
            }
            }
        ],
        "containers": [
            {
            "name": "sleeping-sidecar",
            "image": "alpine",
            "command": ["sleep", "1h"],
            "resources": {},
            "volumeMounts": [
                {
                "name": "default-token-pvpz7",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
                }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
            },
            {
            "name": "nginx",
            "image": "nginx",
            "resources": {},
            "volumeMounts": [
                {
                "name": "default-token-pvpz7",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
                }
            ],
            "securityContext": {
                "privileged": true
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
            }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "default",
        "serviceAccount": "default",
        "securityContext": {},
        "schedulerName": "default-scheduler",
        "tolerations": [
            {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
            },
            {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
            },
            {
            "key": "dedicated",
            "operator": "Equal",
            "value": "tenantA",
            "effect": "NoSchedule"
            }
        ],
        "priority": 0,
        "enableServiceLinks": true,
        "preemptionPolicy": "PreemptLowerPriority"
        },
        "status": {
        "phase": "Pending",
        "qosClass": "BestEffort"
        }
    },
    "oldObject": null,
    "dryRun": false,
    "options": {
        "kind": "CreateOptions",
        "apiVersion": "meta.k8s.io/v1"
    }
  }
}'
```

If you want to visualize the metrics in a Grafana dashboard you can start a Grafana 
instance locally:

```
docker run -d --add-host=host.docker.internal:host-gateway --name=grafana -p 3001:3000 grafana/grafana
```

After that, you can access Grafana WebUI at [localhost:3001](http://localhost:3001), create a Prometheus
data source using the `http://host.docker.internal:9090` as the data source URL,
and [import](https://grafana.com/docs/grafana/latest/dashboards/export-import/#import-dashboard)
the dashboard definition kubewarden-dashboard.json file into the Grafana instance.
