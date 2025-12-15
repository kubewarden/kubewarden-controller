# kubewarden-controller

`kubewarden-controller` is a Kubernetes controller that allows you to
dynamically register Kubewarden admission policies.

The `kubewarden-controller` will reconcile the admission policies you
have registered against the Kubernetes webhooks of the cluster where
it is deployed.

The kubewarden-controller can be deployed using a helm chart.

## Installing the charts

If you want to enable telemetry, you also need to install [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator).

For example:
```console
$ helm repo add kubewarden https://charts.kubewarden.io
$ helm install --create-namespace -n kubewarden kubewarden-crds kubewarden/kubewarden-crds
$ helm install --wait -n kubewarden kubewarden-controller kubewarden/kubewarden-controller
$ helm install --wait -n kubewarden kubewarden-defaults kubewarden/kubewarden-defaults
```

This will install kubewarden-crds, kubewarden-controller, and a
default PolicyServer on the Kubernetes cluster in the default configuration
(which includes self-signed TLS certs).

The default configuration values should be good enough for the majority of
deployments. All the options are documented in the configuration section.

## Upgrading the charts

Please refer to the release notes of each version of the helm charts.
These can be found [here](https://github.com/kubewarden/helm-charts/releases).

## Uninstalling the charts

To uninstall/delete kubewarden-controller and kubewarden-crds use the following
command:

```console
$ helm uninstall -n kubewarden kubewarden-defaults
$ helm uninstall -n kubewarden kubewarden-controller
$ helm uninstall -n kubewarden kubewarden-crds
```

The commands remove all the Kubernetes components associated with the chart, all
policy servers and their policies, and deletes the release along with the release
history.

If you want to keep the history use `--keep-history` flag.

## Configuration

See the `values.yaml` file of the chart for the configuration values.

For the default PolicyServer configuration, Check the `kubewarden-defaults`
chart and its documentation.

# Kubewarden usage

Once the kubewarden-controller is up and running, Kubewarden policies can be
defined via the `ClusterAdmissionPolicy` resource.

The documentation of this Custom Resource can be found
[here](https://github.com/kubewarden/kubewarden-controller/blob/main/docs/crds/README.asciidoc)
or on [docs.crds.dev](https://doc.crds.dev/github.com/kubewarden/kubewarden-controller).

**Note well:** `ClusterAdmissionPolicy` resources are cluster-wide.

### Deploy your first admission policy

The following snippet defines a Kubewarden Policy based on the
[pod-privileged](https://github.com/kubewarden/pod-privileged-policy)
policy:

```yaml
kubectl apply -f - <<EOF
---
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: privileged-pods
spec:
  policyServer: default
  module: registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
        - CREATE
        - UPDATE
  mutating: false
EOF
```

**Note well**: The `ClusterAdmissionPolicy` is deployed in the `default` PolicyServer.
Which is installed in the `kubewarden-defaults` chart. If you do not install
the chart, you should deploy a PolicyServer first. Check out the
[documentation](https://docs.kubewarden.io/quick-start.html#policy-server) for more details

Let's try to create a Pod with no privileged containers:

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: unprivileged-pod
spec:
  containers:
    - name: nginx
      image: nginx:latest
EOF
```

This will produce the following output, which means the Pod was successfully
created:

`pod/unprivileged-pod created`

Now, let's try to create a pod with at least one privileged container:

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: nginx
      image: nginx:latest
      securityContext:
        privileged: true
EOF
```

This time the creation of the Pod will be blocked, with the following message:

```
Error from server: error when creating "STDIN": admission webhook "privileged-pods.kubewarden.admission" denied the request: User 'minikube-user' cannot schedule privileged containers
```

### Remove your first admission policy

You can delete the admission policy you just created:

```console
$ kubectl delete clusteradmissionpolicy privileged-pods
```
