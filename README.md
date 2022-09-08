[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-controller)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller)

Kubewarden is a Kubernetes Dynamic Admission Controller that uses policies written
in WebAssembly.

For more information refer to the [official Kubewarden website](https://kubewarden.io/).

# kubewarden-controller

`kubewarden-controller` is a Kubernetes controller that allows you to
dynamically register Kubewarden admission policies.

The `kubewarden-controller` will reconcile the admission policies you
have registered against the Kubernetes webhooks of the cluster where
it is deployed.

## Installation

The kubewarden-controller can be deployed using a helm chart. For instructions,
see https://charts.kubewarden.io.

## Usage

Once the kubewarden-controller is up and running, Kubewarden policies can be defined
via the `ClusterAdmissionPolicy` resource.

The documentation of this Custom Resource can be found
[here](https://github.com/kubewarden/kubewarden-controller/blob/main/docs/crds/README.asciidoc)
or on [docs.crds.dev](https://doc.crds.dev/github.com/kubewarden/kubewarden-controller).

**Note well:** `ClusterAdmissionPolicy` resources are cluster-wide.

### Deploy your first admission policy

The following snippet defines a Kubewarden Policy based on the
[psp-capabilities](https://github.com/kubewarden/psp-capabilities)
policy:

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: psp-capabilities
spec:
  module: registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.3
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
      - CREATE
      - UPDATE
  mutating: true
  settings:
    allowed_capabilities:
    - CHOWN
    required_drop_capabilities:
    - NET_ADMIN
```

This `ClusterAdmissionPolicy` will evaluate all the `CREATE` and
`UPDATE` operations performed against Pods.
The homepage of this policy provides more insights about how this policy behaves.

Creating the resource inside of Kubernetes is sufficient to enforce the policy:

```shell
$ kubectl apply -f https://raw.githubusercontent.com/kubewarden/kubewarden-controller/main/config/samples/policies_v1alpha2_clusteradmissionpolicy.yaml
```

### Remove your first admission policy

You can delete the admission policy you just created:

```
$ kubectl delete clusteradmissionpolicy psp-capabilities
$ kubectl patch clusteradmissionpolicy psp-capabilities -p '{"metadata":{"finalizers":null}}' --type=merge
```

## Learn more

The [official documentation](https://docs.kubewarden.io) provides more insights
about how the project works and how to use it.

# Software bill of materials

Kubewarden controller has its software bill of materials (SBOM) published every
release. It follows the [SPDX](https://spdx.dev/) version 2.2 format and it can be found
together with the signature and certificate used to signed it in the
[release assets](https://github.com/kubewarden/kubewarden-controller/releases)

# Roadmap

[Roadmap](https://github.com/orgs/kubewarden/projects/2) for the Kubewarden project.
