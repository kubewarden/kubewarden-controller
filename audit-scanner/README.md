## Audit scanner

[![Kubewarden Core Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-core.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#core-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)
[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-controller)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller)
[![codecov](https://codecov.io/gh/kubewarden/audit-scanner/graph/badge.svg?token=EDPPGWJFSK)](https://codecov.io/gh/kubewarden/audit-scanner)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7439/badge)](https://www.bestpractices.dev/projects/7439)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Faudit-scanner.svg?type=shield&issueType=license)](https://app.fossa.com/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Faudit-scanner?ref=badge_shield&issueType=license)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kubewarden/audit-scanner/badge)](https://scorecard.dev/viewer/?uri=github.com/kubewarden/audit-scanner)

> **Note well:** don't forget to checkout [Kubewarden's Audit Scanner documentation](https://docs.kubewarden.io/explanations/audit-scanner)
> for more information

The Audit scanner inspects the resources defined in the cluster and
identifies the ones that are violating Kubewarden policies.

The results of the scan are stored in `PolicyReport` and `ClusterPolicyReports` custom resources.
Each resource has its own dedicated `PolicyReport` or `ClusterPolicyReport`, depending on the type of the resource.

See [Querying the reports](#querying-the-reports) for more information.

# Usage

```console
audit-scanner [flags]

Flags:
  -c, --cluster                       scan cluster wide resources
      --disable-store                 disable storing the results in the k8s cluster
  -f, --extra-ca string               File path to CA cert in PEM format of PolicyServer endpoints
  -h, --help                          help for audit-scanner
  -i, --ignore-namespaces strings     comma separated list of namespace names to be skipped from scan. This flag can be repeated
      --insecure-ssl                  skip SSL cert validation when connecting to PolicyServers endpoints. Useful for development
  -k, --kubewarden-namespace string   namespace where the Kubewarden components (e.g. PolicyServer) are installed (required) (default "kubewarden")
  -l, --loglevel string               level of the logs. Supported values are: [trace debug info warn error fatal] (default "info")
  -n, --namespace string              namespace to be evaluated
  -o, --output-scan                   print result of scan in JSON to stdout
      --page-size int                 number of resources to fetch from the Kubernetes API server when paginating (default 100)
      --parallel-namespaces int       number of Namespaces to scan in parallel (default 1)
      --parallel-policies int         number of policies to evaluate for a given resource in parallel (default 5)
      --parallel-resources int        number of resources to scan in parallel (default 100)
  -u, --policy-server-url string      URI to the PolicyServers the Audit Scanner will query. Example: https://localhost:3000. Useful for out-of-cluster debugging
```

## Examples

Scan the whole cluster:

```shell
audit-scanner  --kubewarden-namespace kubewarden --cluster
```

Scan a single namespace:

```shell
audit-scanner  --kubewarden-namespace kubewarden --namespace default
```

Disable storing the results in etcd and print the reports to stdout in JSON format:

```shell
audit-scanner  --kubewarden-namespace kubewarden --disable-store --output-scan
```

## Tuning

The audit scanner works by entering each Namespace of the cluster and finding all the policies that are "looking" at the contents of the Namespace.
It then identifies all the resource types that are relevant to these policies (e.g. Deployments, Pods, etc.) and iterates over each resource type.

When looking into a specific type of resource, audit-scanner fetches these objects in chunks. The size of the chunk can be set using the `--page-size` flag.
The scanner fetches one chunk of resources, then iterates over each one of them, evaluating all the policies that are looking at that specific resource.

Each iteration step can be done in parallel. The number of Namespaces to be evaluated at the same time can be set using the `--parallel-namespaces` flag.
The number of resources to be evaluated at the same time can be set using the `--parallel-resources` flag.
When evaluating the policies for a specific resource, the number of policies to be evaluated at the same time can be set using the `--parallel-policies` flag.

A concrete example:

- We have 5 namespaces, each with 1000 Pods.
- We have 10 `ClusterAdmissionPolicy` resources that are looking at Pods.
- We have set `--page-size=200`, `--parallel-namespaces=2`, `--parallel-resources=100`, and `--parallel-policies=5`.

The scanner will:

- Work on 2 Namespaces at the same time.
- Inside of each Namespace:
  - Fetch 200 Pods at the same time (`--page-size=200`).
  - Evaluate 100 Pods at the same time (`--parallel-resources=100`).
  - Evaluate 5 policies at the same time (`--parallel-policies=5`).

Things to consider:

- The pagination size has a direct impact on
  - The number of API calls that the scanner will make.
  - The amount of memory that the scanner will use.
- The maximum number of outgoing evaluation requests is the product of `--parallel-namespaces`, `--parallel-resources`, and `--parallel-policies`.

# Querying the reports

Using the `kubectl` command line tool, you can query the results of the scan:

List the reports in the default namespace:

```console
$ kubectl get polr -o wide

NAME                                   KIND         NAME                        PASS   FAIL   WARN   ERROR   SKIP   AGE
009805e4-6e16-4b70-80c9-cb33b6734c82   Deployment   deployment1                 5      1      0      0       0      1h
011e8ca7-40d5-4e76-8c89-6f820e24f895   Deployment   deployment2                 2      4      0      0       0      1h
02c28ab7-e332-47a2-9cc2-fe0fad5cd9ad   Pod          pod1                        10     0      0      0       0      1h
04937b2b-e68b-47d5-909d-d0ae75527f07   Pod          pod2                        9      1      0      0       0      1h
...
```

List the cluster-wide reports:

```console
$ kubectl get cpolr -o wide

NAME                                   KIND        NAME                 PASS   FAIL   WARN   ERROR   SKIP   AGE
261c9492-deec-4a09-8aa9-cd464bb4b8d1   Namespace   namespace1           3      1     0       0       0      1h
35ca342f-685b-4162-a342-8d7a52a61749   Namespace   namespace2           0      4     0       0       0      1h
3a8f8a88-338b-4905-b9e4-f13397a0d7b5   Namespace   namespace3           4      0     0       0       0      15h
```

Get the details of a specific report:

```console
$ kubectl get polr 009805e4-6e16-4b70-80c9-cb33b6734c82 -o yaml
```

Result:

```yaml
apiVersion: wgpolicyk8s.io/v1beta1
kind: PolicyReport
metadata:
  creationTimestamp: "2024-02-29T06:55:37Z"
  generation: 6
  labels:
    app.kubernetes.io/managed-by: kubewarden
  name: 009805e4-6e16-4b70-80c9-cb33b6734c82
  namespace: default
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: deployment1
      uid: 009805e4-6e16-4b70-80c9-cb33b6734c82
  resourceVersion: "2685996"
  uid: c5a88847-d678-4733-8120-1b83fd6330cb
results:
  - category: Resource validation
    message: "The following mandatory labels are missing: cost-center"
    policy: clusterwide-safe-labels
    properties:
      policy-resource-version: "2684810"
      policy-uid: 826dd4ef-9db5-408e-9482-455f278bf9bf
      policy-name: safe-labels
      validating: "true"
    resourceSelector: {}
    result: fail
    scored: true
    severity: low
    source: kubewarden
    timestamp:
      nanos: 0
      seconds: 1709294251
# other results...
scope:
  apiVersion: apps/v1
  kind: Deployment
  name: deployment1
  namespace: default
  resourceVersion: "3"
  uid: 009805e4-6e16-4b70-80c9-cb33b6734c82
summary:
  error: 0
  fail: 10
  pass: 0
  skip: 0
  warn: 0
```

# Deployment

The Audit Scanner is deployed as a part of the [Kubewarden Controller helm chart](https://github.com/kubewarden/helm-charts).
Please refer to the [Kubewarden Controller documentation](https://docs.kubewarden.io/installation/installation) for more information.

# Building

You can use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/kubewarden/packages/container/package/audit-scanner).

Alternatively, the `audit-scanner` binary can be built in this way:

```shell
make build
```

Please refer [CONTRIBUTING.md](CONTRIBUTING.md) for more information on how to contribute to this project.

For implementation details, see [RFC-11](https://github.com/kubewarden/rfc/blob/main/rfc/0011-audit-checks.md),
[RFC-12](https://github.com/kubewarden/rfc/blob/main/rfc/0012-policy-report.md).

# Software bill of materials

Audit scanner has its software bill of materials (SBOM
[SPDX](https://spdx.dev/)) and
[Provenance](https://slsa.dev/spec/v1.0/provenance) files published every
release. Both files are generated by [Docker
buildx](https://docs.docker.com/build/metadata/attestations/) during the build
process and stored in the container registry together with the container image
as well as uploaded to the release page. 

After the container image building, the container image and their attestations
are signed using cosign. The attestation files are stored inside a tarball with
the checksum file with the sha256sum for the files there. Therefore, after
downloading the attestation files from the [release
page](https://github.com/kubewarden/audit-scanner/releases), extracting them,
you can verify the checksum file signature using the following command:

```shell
cosign verify-blob --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity="https://github.com/kubewarden/audit-scanner/.github/workflows/attestation.yml@refs/tags/v1.17.0" \
    --bundle audit-scanner-attestation-arm64-checksum-cosign.bundle \
    audit-scanner-attestation-arm64-checksum.txt
```

If you want to verify the attestation manifest and its layer signatures, you
can use the following command:

```shell
cosign verify --certificate-oidc-issuer=https://token.actions.githubusercontent.com  \
    --certificate-identity="https://github.com/kubewarden/audit-scanner/.github/workflows/attestation.yml@refs/tags/v1.17.0 \
    ghcr.io/kubewarden/audit-scanner@sha256:1abc0944378d9f3ee2963123fe84d045248d320d76325f4c2d4eb201304d4c4e
```

Remember that the sha256 hash is the digest of the attestation manifest or its
layers. Therefore, you need to find this info in the registry using the UI or
tools like `crane`. For example, the following command will show you all the
attestation manifests of the `latest` tag:

```shell
crane manifest  ghcr.io/kubewarden/audit-scanner:latest | jq '.manifests[] | select(.annotations["vnd.docker.reference.type"]=="attestation-manifest")'
{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "digest": "sha256:fc01fa6c82cffeffd23b737c7e6b153357d1e499295818dad0c7d207f64e6ee8",
  "size": 1655,
  "annotations": {
    "vnd.docker.reference.digest": "sha256:611d499ec9a26034463f09fa4af4efe2856086252d233b38e3fc31b0b982d369",
    "vnd.docker.reference.type": "attestation-manifest"
  },
  "platform": {
    "architecture": "unknown",
    "os": "unknown"
  }
}
{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "digest": "sha256:e0cd736c2241407114256e09a4cdeef55eb81dcd374c5785c4e5c9362a0088a2",
  "size": 1655,
  "annotations": {
    "vnd.docker.reference.digest": "sha256:03e5db83a25ea2ac498cf81226ab8db8eb53a74a2c9102e4a1da922d5f68b70f",
    "vnd.docker.reference.type": "attestation-manifest"
  },
  "platform": {
    "architecture": "unknown",
    "os": "unknown"
  }
}
```

Then you can use the `digest` field to verify the attestation manifest and its
layers signatures.

```shell
cosign verify --certificate-oidc-issuer=https://token.actions.githubusercontent.com  \
    --certificate-identity="https://github.com/kubewarden/audit-scanner/.github/workflows/attestation.yml@refs/tags/v1.17.0 \
    ghcr.io/kubewarden/audit-scanner@sha256:fc01fa6c82cffeffd23b737c7e6b153357d1e499295818dad0c7d207f64e6ee8

crane manifest  ghcr.io/kubewarden/audit-scanner@sha256:fc01fa6c82cffeffd23b737c7e6b153357d1e499295818dad0c7d207f64e6ee8
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:eda788a0e94041a443eca7286a9ef7fce40aa2832263f7d76c597186f5887f6a",
    "size": 463
  },
  "layers": [
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:563689cdee407ab514d057fe2f8f693189279e10bfe4f31f277e24dee00793ea",
      "size": 94849,
      "annotations": {
        "in-toto.io/predicate-type": "https://spdx.dev/Document"
      }
    },
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:7ce0572628290373e17ba0bbb44a9ec3c94ba36034124931d322ca3fbfb768d9",
      "size": 7363045,
      "annotations": {
        "in-toto.io/predicate-type": "https://spdx.dev/Document"
      }
    },
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:dacf511c5ec7fd87e8692bd08c3ced2c46f4da72e7271b82f1b3720d5b0a8877",
      "size": 71331,
      "annotations": {
        "in-toto.io/predicate-type": "https://spdx.dev/Document"
      }
    },
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:594da3e8bd8c6ee2682b0db35857933f9558fd98ec092344a6c1e31398082f4d",
      "size": 980,
      "annotations": {
        "in-toto.io/predicate-type": "https://spdx.dev/Document"
      }
    },
    {
      "mediaType": "application/vnd.in-toto+json",
      "digest": "sha256:7738d8d506c6482aaaef1d22ed920468ffaf4975afd28f49bb50dba2c20bf2ca",
      "size": 13838,
      "annotations": {
        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"
      }
    }
  ]
}

cosign verify --certificate-oidc-issuer=https://token.actions.githubusercontent.com  \
    --certificate-identity="https://github.com/kubewarden/audit-scanner/.github/workflows/attestation.yml@refs/tags/v1.17.0 \
    ghcr.io/kubewarden/audit-scanner@sha256:594da3e8bd8c6ee2682b0db35857933f9558fd98ec092344a6c1e31398082f4d
```

Note that each attestation manifest (for each architecture) has its own layers.
Each layer is a different SBOM SPDX or provenance files generated by Docker
Buildx during the multi stage build process. You can also use `crane` to
download the attestation file:

```shell
crane blob ghcr.io/kubewarden/audit-scanner@sha256:7738d8d506c6482aaaef1d22ed920468ffaf4975afd28f49bb50dba2c20bf2ca
```

# Security

The Kubewarden team is security conscious. You can find our [threat model
assessment](https://docs.kubewarden.io/security/threat-model) and
[responsible disclosure approach](https://docs.kubewarden.io/security/disclosure)
in our Kubewarden docs.

## Security disclosure

See [SECURITY.md](https://github.com/kubewarden/community/blob/main/SECURITY.md) on the kubewarden/community repo.

# Changelog

See [GitHub Releases content](https://github.com/kubewarden/audit-scanner/releases).
