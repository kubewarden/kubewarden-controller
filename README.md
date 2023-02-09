[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-controller)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6502/badge)](https://bestpractices.coreinfrastructure.org/projects/6502)
[![E2E](https://github.com/kubewarden/kubewarden-controller/actions/workflows/e2e-tests.yml/badge.svg)](https://github.com/kubewarden/kubewarden-controller/actions/workflows/e2e-tests.yml)
[![FOSSA license scan](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fkubewarden-controller.svg?type=shield)](https://app.fossa.com/projects/custom%252B25850%252Fgithub.com%252Fkubewarden%252Fkubewarden-controller?ref=badge_shield)

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

# Governance

See our [governance document](https://github.com/kubewarden/rfc/blob/main/rfc/0013-governance.md).

# Community meeting

We host regular online meetings for contributors, adopters, maintainers, and anyone else interested to connect in a synchronous fashion. These meetings usually take place on second Thursday of the month at 4PM UTC.

* [Zoom link](https://zoom.us/j/92928111886)
* [Minutes from previous meetings](https://docs.google.com/document/d/1TgPIFKygkR2_vViCSfBEzwDDactfTcedc9fc4AeVJ9w/edit#)
* [Recordings from previous meetings](https://zoom.us/rec/play/rbKlB87WT6JnrwqpRfW3qf3K_nDNCPtesTGAbpEPCL00iAL3_AY0W2tIKo6J1hEDaXk2d2UiQAU_dK4f.msiYZPm5EDxvEDEs?continueMode=true&_x_zm_rtaid=nGiNSrS6ThO04eVz4BHwwg.1675944628679.a37d04739bbd2c6cbbe6de1d9030b1e1&_x_zm_rhtaid=993)

We're a friendly group, so please feel free to join us!

# Community

- Slack: [#kubewarden](https://kubernetes.slack.com/archives/kubewarden) and [#kubewarden-dev](https://kubernetes.slack.com/archives/kubewarden-dev)

