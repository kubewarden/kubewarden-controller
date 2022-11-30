# Contributing

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

In order to execute this Makefile target, you need to have created a
Kubernetes cluster with `k3d`, `kind` or `minikube` that is reachable
through your `~/.kube/config` kubeconfig file.

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

The Subject Alternative Names of the generated certificate in
development mode will contain whatever was provided on
`WEBHOOK_HOST_ADVERTISE` (or whatever it was defaulted to, if it was
not provided).

### Install Custom Resource Definitions

Before running the controller, install the custom resource definitions:

```console
kubectl apply -f config/crd/bases
```

### Create the `kubewarden` namespace

```console
kubectl create ns kubewarden
```

### Running

#### Running with k3d

```console
KUBEWARDEN_DEVELOPMENT_MODE=1 \
  WEBHOOK_HOST_LISTEN=$(docker inspect k3d-k3s-default-server-0 | jq -r '.[] | .NetworkSettings.Networks."k3d-k3s-default".Gateway') \
  make run
```

#### Running with kind

```console
KUBEWARDEN_DEVELOPMENT_MODE=1 \
  WEBHOOK_HOST_LISTEN=$(docker inspect kind-control-plane | jq -r '.[] | .NetworkSettings.Networks.kind.Gateway') \
  make run
```

#### Running with minikube

```console
KUBEWARDEN_DEVELOPMENT_MODE=1 \
  WEBHOOK_HOST_LISTEN=0.0.0.0 \
  WEBHOOK_HOST_ADVERTISE=host.minikube.internal \
  make run
```

## Tagging a new release

### Make sure CRD docs are updated:

```console
$ cd docs/crds
$ make generate
$ # commit resulting changes
```

### Create a new tag

Assuming your official kubewarden remote is called `upstream`:

```console
$ git commit -m 'Update CHANGELOG.md' # on main branch
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

Now that the controller has a new tag released, consider bumping the
[`helm-chart`](https://github.com/kubewarden/helm-charts/tree/main/charts/kubewarden-controller).

### Consider announcing the new release in channels!

