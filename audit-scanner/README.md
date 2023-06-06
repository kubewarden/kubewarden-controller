## Audit scanner

[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-controller)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller)
<!-- [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6626/badge)](https://bestpractices.coreinfrastructure.org/projects/6626) -->
<!-- [![FOSSA Status](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Faudit-scanner.svg?type=shield)](https://app.fossa.com/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Faudit-scanner?ref=badge_shield) -->

> **Note well:** don't forget to checkout [Kubewarden's documentation](https://docs.kubewarden.io)
> for more information

The Audit scanner inspects the resources defined in the cluster and
identifies the ones that are violating Kubewarden policies.

The results of the scan are made available via `PolicyReport` objects. Each Namespace
has its own dedicated `PolicyReport`. Cluster-wide resources compliance is available via
the `ClusterPolicyReport` resource. 

# Deployment

We recommend to rely on the [kubewarden-controller](https://github.com/kubewarden/kubewarden-controller)
and the [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
provided by it to deploy the Kubewarden stack.

# Building

You can use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/kubewarden/packages/container/package/audit-scanner).

Alternatively, the `audit-scanner` binary can be built in this way:

```shell
$ make build
```

Have a look at CONTRIBUTING.md for more developer information.

For implementation details, see [RFC-11](https://github.com/kubewarden/rfc/blob/main/rfc/0011-audit-checks.md), 
[RFC-12](https://github.com/kubewarden/rfc/blob/main/rfc/0012-policy-report.md).


# Software bill of materials

Audit scanner has its software bill of materials (SBOM) published every release.
It follows the [SPDX](https://spdx.dev/) version 2.2 format and it can be found
together with the signature and certificate used to signed it in the
[release assets](https://github.com/kubewarden/audit-scanner/releases)


# Security

The Kubewarden team is security conscious. You can find our [threat model
assessment](https://docs.kubewarden.io/security/threat-model) and
[responsible disclosure approach](https://docs.kubewarden.io/security/disclosure)
in our Kubewarden docs.
