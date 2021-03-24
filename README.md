Chimera is a Kubernetes Dynamic Admission Controller that uses policies written
in WebAssembly.

For more information refer to the [official Chimera website](https://chimera-kube.github.io/).

# chimera-controller

`chimera-controller` is a Kubernetes controller that allows you to
dynamically register Chimera admission policies.

The `chimera-controller` will reconcile the admission policies you
have registered against the Kubernetes webhooks of the cluster where
it is deployed.

## Installation

The chimera-controller can be deployed using a helm chart:

```shell
$ helm repo add chimera https://chimera-kube.github.io/helm-charts/
$ helm install chimera-controller chimera/chimera-controller
```

This will install chimera-controller on the Kubernetes cluster in the default
configuration.

The default configuration values should be good enough for the majority of
deployments, all the options are documented
[here](https://chimera-kube.github.io/helm-charts/#configuration).

## Usage

Once the chimera-controller is up and running, Chimera policies can be definied
via the `AdmissionPolicy` resource.

The documentation of this Custom Resource can be found
[here](https://github.com/chimera-kube/chimera-controller/blob/main/docs/crds/README.asciidoc)
or on [docs.crds.dev](https://doc.crds.dev/github.com/chimera-kube/chimera-controller).

**Note well:** `AdmissionPolicy` resources are cluster-wide.

### Deploy your first admission policy

The following snippet defines a Chimera Policy based on the
[pod-privileged](https://github.com/chimera-kube/pod-privileged-policy)
policy:

```yaml
apiVersion: chimera.suse.com/v1alpha1
kind: AdmissionPolicy
metadata:
  name: privileged-pods
spec:
  module: registry://ghcr.io/chimera-kube/policies/pod-privileged:v0.1.0
  resources:
  - pods
  operations:
  - CREATE
  - UPDATE
  settings:
    trusted_users:
    - alice
  mutating: false
```

This `AdmissionPolicy` will evaluate all the `CREATE` and `UPDATE` operations performed
against Pods. Only the user `alice` will be allowed to create privileged Pods.

Creating the resource inside of Kubernetes is sufficient to enforce the policy:

```shell
$ kubectl apply -f https://raw.githubusercontent.com/chimera-kube/chimera-controller/v0.1.0/config/samples/chimera_v1alpha1_admissionpolicy.yaml
```

### Remove your first admission policy

You can delete the admission policy you just created:

```
$ kubectl delete admissionpolicy privileged-pod
```
