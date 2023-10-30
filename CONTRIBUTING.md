# Contributing

This document contains instructions on how to build and run locally the controller
allowing developers to test their changes.

## Building

To build kubewarden-controller some packages are required. If you are using
openSUSE Leap, you can install them with the following command:

```
sudo zypper in -y make go
```

Then, can run the following command to build the package:

```
make
```

## Running

You can run the controller by executing `make run`. This Makefile
target executes the controller locally as a regular process.

In order to execute this Makefile target, you need to have created a Kubernetes
cluster with that is reachable through your `~/.kube/config` kubeconfig file.

These are the relevant environment variables:

- `KUBEWARDEN_DEVELOPMENT_MODE`: if its value is `1` or `true`, the
  controller will generate certificates and register Kubewarden
  webhooks in the configured default Kubernetes cluster present in the
  current context in the kubeconfig file.

- `WEBHOOK_HOST_LISTEN`: host or IP address where the webhook server
  is listening. Only applicable if `KUBEWARDEN_DEVELOPMENT_MODE` is
  enabled. If not provided and `WEBHOOK_HOST_ADVERTISE` is provided,
  it will be defaulted to `WEBHOOK_HOST_ADVERTISE`.

- `WEBHOOK_HOST_ADVERTISE`: how the API server will try to reach the
  webhook endpoint. Only applicable if `KUBEWARDEN_DEVELOPMENT_MODE` is
  enabled. If not provided and `WEBHOOK_HOST_LISTEN` is provided,
  it will be defaulted to `WEBHOOK_HOST_LISTEN`.

The Subject Alternative Names of the generated certificate in development mode
will contain whatever was provided on `WEBHOOK_HOST_ADVERTISE` (or whatever it
was defaulted to, if it was not provided).

To run the controller in the developer workstation it's possible to use
[telepresence](https://github.com/telepresenceio/telepresence). It allows
developers to "add" the local workstation in the cluster. Thus, it's possible
to access workloads in the cluster and receive requests to the controller running
in the developer machine.  

> Install the telepresence binary from the Github releases page. The official 
> once from Ambassador Labs may require login. 

Before running the controller, install the custom resource definitions:

```console
kubectl apply -f config/crd/bases
```

Create the `kubewarden` namespace

```console
kubectl create ns kubewarden
```

Now, as we are using `telepresence` to intercept the intra cluster
communication, we need to create the controller deployment and service that
`telepresence` will intercept. For this, install the Kuberwarden stack
following the steps described quickstart guide. In other words, install
Kubewarden controller helm chart. However, a change is required. The controller
deployment must allow root users. This is disable by default and it is required
because `telepresence` will add a init container in the deployment which need
root access.

```console
# Remember to install the requirements needed. See the quickstart guide for more information
kubectl apply -f https://github.com/jetstack/cert-manager/releases/latest/download/cert-manager.yaml
kubectl wait --for=condition=Available deployment --timeout=2m -n cert-manager --all
helm install --wait -n kubewarden  kubewarden-controller kubewarden/kubewarden-controller
```



Now, install `telepresence` in the cluster and connect it to the `kubewarden` namespace

```console
telepresence helm install
telepresence connect -n kubewarden
```

At this point you should be able to reach workloads running in the cluster. To validate
this use a `curl` command:

```console
curl -XGET --insecure https://kubewarden-controller-webhook-service.kubewarden.svc.cluster.local/mutate-policies-kubewarden-io-v1-admissionpolicy
```

In order to avoid two controllers trying to reconcile the same resources, it's necessary to
remove the deployment installed by the `kubewarden-controller` helm chart and deploy a dummy
deployment just to allow `telepresence` to intercept the communications.

```console
kubectl delete deployment -n kubewarden kubewarden-controller
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app.kubernetes.io/instance: kubewarden-controller
    app.kubernetes.io/name: kubewarden-controller
  name: kubewarden-controller
  namespace: kubewarden
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: kubewarden-controller
      app.kubernetes.io/name: kubewarden-controller
  template:
    metadata:
      labels:
        app.kubernetes.io/instance: kubewarden-controller
        app.kubernetes.io/name: kubewarden-controller
    spec:
      containers:
      - name: echo-server
        image: gcr.io/google-containers/echoserver:1.8
        ports:
        - containerPort: 9443
      serviceAccount: kubewarden-controller
      serviceAccountName: kubewarden-controller
  replicas: 1
EOF
```

> Note: if you want to use some kind o NetworkPolicy to block the original controller traffic
> you may need to have a multi node cluster. Because in a single node cluster the traffic 
> policies will not be applied. Because the traffic will not leave the node and never the
> checked against the network policies

To intercept requests sent to the Kubewarden controller run the following command:

```console
telepresence intercept kubewarden-controller --port 9443:443
```

> You can use the `telepresence list` command to check out other services available to
> intercept communication

This command will trigger a new controller pod with the `telepresence` agent which
will reroute the request to the pod for your local machine. Therefore, the developer
can run the controller locally to start receiving the requests:

```console
WEBHOOK_HOST_LISTEN=127.0.0.1 make run
```

After that, when a request is sent to the Kubewarden controller service, your
local instance should handle it. Try again:


```console
curl -XGET --insecure https://kubewarden-controller-webhook-service.kubewarden.svc.cluster.local/mutate-policies-kubewarden-io-v1-admissionpolicy
```

If you want to remove controller interception, use the `leave` subcommand. It make
the service running in the cluster start to receiving the requests again:

```console
telepresence leave kubewarden-controller
```

After that, if you want to remove all the agents added by the `telepresence` in
the controller pod, run:

```console
telepresence uninstall --all-agents
```

Remember to disconnect `telepresence` from cluster that it is connected:

```console
telepresence quit
```

If you forget to quit, next time you try to connect into a cluster, some errors
can happen. 

Finally, if you want to uninstall the `telepresence` stack from the cluster if
the `helm` subcommand:

```console
telepresence helm uninstall
```

## Tagging a new release

Make sure CRD docs are updated:

```console
$ cd docs/crds
$ make generate
$ # commit resulting changes
```

Create a new tag, assuming your official kubewarden remote is called `upstream`:

```console
$ git tag -a vX.Y.Z  -m "vX.Y.Z" -s
$ git push upstream main vX.Y.Z
```

Check that the Github actions are properly executed and have no
errors. With regards to the release, several automation tasks should
have been started:

1. Execute tests
1. Create a new Github release
1. Push a tagged container image with the build of the project

For a release to be complete, all these tasks should have been
executed successfully.

### Consider bumping the helm-chart

Now that the controller has a new tag released, the automation will bump the
[`helm-chart`](https://github.com/kubewarden/helm-charts/tree/main/charts/kubewarden-controller).

### Consider announcing the new release in channels!

