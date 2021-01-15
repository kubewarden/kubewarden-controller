> **Note well:** don't forget to checkout [Chimera's
> documentation](https://chimera-kube.github.io/chimera-book/) for
> more information

# chimera-controller

`chimera-controller` is a Kubernetes controller that allows you to
dynamically register admission policies.

The `chimera-controller` will reconcile the admission policies you
have registered against the Kubernetes webhooks of the cluster where
it is deployed.

## Deployment

### Prerequisites

All you need is a Kubernetes cluster already running. You can use
[`kind`](https://kind.sigs.k8s.io/) if you want to just kick the tires
in a fast fashion.

We will need `cert-manager`, which is required by the
`chimera-controller` webhooks, since this controller has webhooks of
its own:

```
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml
$ kubectl wait --for=condition=Available deployment --timeout=2m -n cert-manager --all
```

### Deploy the controller

Now that all prerequisites are met, we can go ahead and deploy the
`chimera-controller`:

```
$ kubectl apply -f https://raw.githubusercontent.com/chimera-kube/chimera-controller/main/config/generated/all.yaml
$ kubectl wait --for=condition=Available deployment --timeout=2m -n chimera-controller-system --all
```

### Deploy your first admission policy

Now, create a sample admission policy:

```
$ kubectl apply -f https://raw.githubusercontent.com/chimera-kube/chimera-controller/main/config/samples/chimera_v1alpha1_admissionpolicy.yaml
```

### Remove your first admission policy

You can delete the admission policy you just created:

```
$ kubectl delete admissionpolicy admissionpolicy-sample
```

## Anatomy of the controller

If you deployed the controller with the provided manifests, you will
notice that the main following resources were created:

* Namespace: `chimera-controller-system`
  * Deployment: `chimera-controller-manager`
  * Controller Webhooks
    * Defaulting and validation `chimera-controller` webhooks for its
      own custom API types

### API description

You can find the documentation for the `v1alpha` types in [godoc by
clicking
here](https://godoc.org/github.com/chimera-kube/chimera-controller/api/v1alpha1).

If you followed the README, you have already deployed an admission
policy sample resource; it looks like this:

```yaml
apiVersion: chimera.suse.com/v1alpha1
kind: AdmissionPolicy
metadata:
  name: admissionpolicy-sample
spec:
  module: registry://ghcr.io/chimera-kube/policies/pod-toleration:v0.0.2
  resources:
  - pods
  operations:
  - CREATE
  - UPDATE
  env:
    TAINT_KEY: dedicated
    TAINT_VALUE: tenantA
    ALLOWED_GROUPS: system:masters
```

Admission policies are cluster-wide resources. It's possible to create
or delete them (modification of the `spec` is not yet supported --
it's necessary to recreate the resource).

Let's examine the `spec` attributes:

* `module`: this is the location of the WASM module and the supported
  schemes are:
  * `registry`: OCI-compliant registry that supports the artifacts
    spec.
  * `http` or `https`: WASM module served on a regular HTTP server.

* `resources`: describes for what type of resources this webhook
  should be listening to and is able to reject requests.
  * `*` has the catch-all special meaning.

* `operations`: describes for what type of operations on the previous
  resources this webhook should be listening to and is able to reject
  resources.
  * Allowed values: `*` (catch-all), `CREATE`, `UPDATE`, `DELETE`, `CONNECT`.

* `env`: a map of key-values exported to the WASM module declared in
  `module`, so you are able to configure further settings on the WASM
  module itself if required.

### Reconciliation

When a new `AdmissionPolicy` resource is created, the controller will
perform the following actions:

* Ensure that a secret named after the admission policy on the
  `chimera-controller-system` namespace with a generated CA
  certificate, and a server certificate exists.

* Ensure that a deployment and a service named after the admission
  policy on the `chimera-controller-system` exists. This deployment
  will execute the
  [`chimera-admission`](https://github.com/chimera-kube/chimera-admission)
  project with the right environment variables, so there is a
  `chimera-admission` deployment per `AdmissionPolicy` created in the
  system. In the future, this can be improved so the
  `chimera-admission` project could multiplex several WASM modules in
  the same instance -- at the time of writing is a 1:1 relationship.

* Ensure that an Kubernetes admission registration resource exists
  pointing to the created service previously, effectively enabling the
  webhook on the Kubernetes installation.

When an `AdmissionPolicy` resource is created, a `chimera/cleanup`
finalizer is automatically added to the `AdmissionPolicy` resource if
not present. This gives the `chimera-controller` the chance to cleanup
when admission policies are deleted.

When an `AdmissionPolicy` is deleted, the deployment, service and
secret named after the admission policy on the namespace will be
deleted, as well as the cluster-wide admission registration
resource. After all this tasks have succeeded, the
`chimera-controller` will patch the `AdmissionPolicy` resource
removing the finalizer, and so letting Kubernetes eventually GC the
admission policy.
