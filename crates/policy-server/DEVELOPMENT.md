# List of tips and trick for developers

## Tracing

It's easier to test tracing locally, without having to deploy Policy Server into
kubernetes.

Following this tutorial you will end up with the following setup:

- policy-server: running locally, uncontainerized
- OpenTelemetry collector: running locally, inside of a container
- Jaeger all-in-one: running locally, inside of a container
- Prometheus: running locally, inside of a container
- Grafana: running locally, inside of a container

As a first step, start the development docker-compose:

```console
cd hack && docker-compose up -d
```

Now start policy-server:

```console
cargo run --release -- \
  --policies policies.yml \
  --workers 2 \
  --log-fmt otlp \
  --log-level debug \
  --enable-metrics true \
  --ignore-kubernetes-connection-failure true
```

Some notes about this command:

- We are running policy-server in release mode. That's because wasmtime is
  pretty slow at initializing WASM modules when ran in `debug` mode.
- You must provide a `policies.yml` file, you can take inspiration from `policies.yml.example`

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

If you want to visualize the metrics, you can access Grafana WebUI at [localhost:3001](http://localhost:3001),
and [import](https://grafana.com/docs/grafana/latest/dashboards/export-import/#import-dashboard)
the dashboard definition kubewarden-dashboard.json file into the Grafana instance.
Be sure to select the `Prometheus` datasource.

## Debugging policy-server pod

The policy-server container is built from scratch, hence it doesn't have a
shell to do `kubectl exec -ti policy-server -- sh`.

Starting from k8s 1.24, we can use ephemeral containers. Ephemeral containers become sidecars of the
running pod. To instantiate them you can't define their yaml, you need to use `kubectl debug`.

The policy-server process in the policy-server container is running under its own kernel namespace.
To be able to debug it, we need to make a full copy of it. This copy will have an ephemeral container
included in the same kernel namespace, so we have access.

```console
$ kubectl debug --copy-to <name of new debug pod> --share-processes --image alpine -ti <running policy-server pod>
# ps aux
(find PID of policy-server)
```

### Accessing the filesystem of the policy-server container

The filesystem is mounted still in the other container, and cannot be shared
to the alpine one (there would be clashes):

```console
# cd /proc/<PID of policy-server>/
# ls root
ls: root: Permission denied
```

For that, we create a user with UID of user running the policy-server process.
This information can be found by looking at the output of the `ps aux` command.
Currently, the UID of the user running the policy-server is hardcoded inside
of our container image to be `65533`.

```console
# adduser -G nogroup -u <UID of policy-server> -D kw
# su - kw
$ cd /proc/<PID of policy-server>/root
```

As soon as we move into this directory the following error is printed:

```console
ash: getcwd: No such file or directory
```

That's fine, is caused by the shell not being able to determine the current directory.
This error can be ignored, or completely removed by executing this command:

```console
$ export PS1="\h: $ "
```

Next, we can peek into the filesystem of the container running the policy-server process:

```console
$ ls -l
config         dev            etc            pki            policy-server  proc           sys            tmp            var
```

> **Note:** the filesytem of the policy-server container is read-only. This is set inside of the Deployment of the Policy Server.

### Attaching with strace to the policy-server process

From the debugging container, install the `strace` utility. This must be done as
root:

```console
# apk add strace
```

In this special context, strace must be run by the same user running the policy-server
process.

In the previous section you have created a `kw` user. We can leverage that user:

```console
# su - kw
$ strace -p <PID of policy server>
```
