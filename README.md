[![Kubewarden Core Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-core.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#core-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)
[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-controller)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6502/badge)](https://bestpractices.coreinfrastructure.org/projects/6502)
[![E2E](https://github.com/kubewarden/kubewarden-controller/actions/workflows/e2e-tests.yml/badge.svg)](https://github.com/kubewarden/kubewarden-controller/actions/workflows/e2e-tests.yml)
[![FOSSA license scan](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fkubewarden-controller.svg?type=shield)](https://app.fossa.com/projects/custom%252B25850%252Fgithub.com%252Fkubewarden%252Fkubewarden-controller?ref=badge_shield)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kubewarden/kubewarden-controller/badge)](https://scorecard.dev/viewer/?uri=github.com/kubewarden/kubewarden-controller)
[![CLOMonitor](https://img.shields.io/endpoint?url=https://clomonitor.io/api/projects/cncf/kubewarden/badge)](https://clomonitor.io/projects/cncf/kubewarden)

Kubewarden is a Kubernetes Dynamic Admission Controller that uses policies written
in WebAssembly.

For more information refer to the [official Kubewarden website](https://kubewarden.io/).

# kubewarden-controller

`kubewarden-controller` is a Kubernetes controller that allows you to
dynamically register Kubewarden admission policies.

The `kubewarden-controller` reconciles the admission policies you
have registered with the Kubernetes webhooks of the cluster where
it's deployed.

## Installation

The kubewarden-controller can be deployed using a Helm chart. For instructions,
see https://charts.kubewarden.io.

## Usage

Once the kubewarden-controller is up and running, you can define Kubewarden policies
using the `ClusterAdmissionPolicy` resource.

The documentation of this Custom Resource can be found
[here](https://github.com/kubewarden/kubewarden-controller/blob/main/docs/crds/README.asciidoc)
or on [docs.crds.dev](https://doc.crds.dev/github.com/kubewarden/kubewarden-controller).

**Note:** `ClusterAdmissionPolicy` resources are cluster-wide.

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

This `ClusterAdmissionPolicy` evaluates all the `CREATE` and `UPDATE` operations
performed against Pods. The homepage of this policy provides more insights about
how this policy behaves.

Creating the resource inside Kubernetes is sufficient to enforce the policy:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubewarden/kubewarden-controller/main/config/samples/policies_v1alpha2_clusteradmissionpolicy.yaml
```

### Remove your first admission policy

You can delete the admission policy you just created:

```console
kubectl delete clusteradmissionpolicy psp-capabilities
kubectl patch clusteradmissionpolicy psp-capabilities -p '{"metadata":{"finalizers":null}}' --type=merge
```

## Learn more

The [documentation](https://docs.kubewarden.io) provides more insights
about how the project works and how to use it.

# Software bill of materials

Kubewarden controller has its software bill of materials (SBOM) published every
release. It follows the [SPDX](https://spdx.dev/) version 2.2 format and you can
find it together with the signature and certificate used to sign it in the
[release assets](https://github.com/kubewarden/kubewarden-controller/releases)

## Security disclosure

See [SECURITY.md](https://github.com/kubewarden/community/blob/main/SECURITY.md) on the kubewarden/community repo.

# Changelog

See [GitHub Releases content](https://github.com/kubewarden/kubewarden-controller/releases).
