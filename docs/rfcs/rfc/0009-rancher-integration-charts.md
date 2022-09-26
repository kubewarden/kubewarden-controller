|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Rancher integration of Kubewarden charts  |
| Start Date   | 2022-08-22                       |
| Category     | Development                      |
| RFC PR       | https://github.com/kubewarden/rfc/pull/11  |
| State        | **ACCEPTED**                     |


# Summary
[summary]: #summary

This RFC explains how the Kubewarden Helm charts, owned by the Kubewarden team,
can be integrated in Rancher Explorer.

It proposes that the needed Rancher Helm charts and Rancher Packages artifacts
metadata are added to the Kubewarden Helm charts. If additional non-backwards
compatible changes are needed, they can tracked in a separate branch.


# Motivation
[motivation]: #motivation

Problems to solve:

- Show and install kubewarden Helm charts through Rancher Explorer UI.
- Implement it efficiently and with low development maintenance costs.
- Allow for airgap installations.

## Examples / User Stories
[examples]: #examples

1. As a user, I want to install Kubewarden via Rancher Explorer UI. This means
   that the Kubewarden stack will be a predefined Application in Rancher
   Explorer UI, and the needed dependencies will be automatically pulled when
   installing charts, or the Rancher UI will take care of installing them.
2. As a user, I want to uninstall Kubewarden via Rancher Explorer UI, in a
   controlled manner, so the cluster is left in a working state.
3. As a user, I want to install the Kubewarden defaults chart, and be sure that
   those defaults don't hinder the default configuration of the local cluster
   administered via Rancher Explorer UI.
4. As a user, I want to upgrade and reconfigure the Kubewarden stack via Rancher
   Explorer UI.

# Detailed design
[design]: #detailed-design

Submission and inclusion into the Rancher charts repository is done by using
Rancher Packages in https://github.com/rancher/charts.

A Package represents a grouping of one or more Helm Charts. Every Package must
have exactly one Chart designated as a main Chart (multiple main Charts are not
supported at this time) and all other Charts will be considered
`additionalCharts`.

Packages can carry patches to the upstream charts, and are processed and
rendered into usual Helm charts that get served via a typical Helm chart
repository. Rancher Helm charts created for use in Rancher products are
augmented in a backwards-compatible way with Helm charts by adding
`annotations` to `Chart.yml`.

The Rancher charts generation from our Rancher Package should be kept to a
minimum. Ideally, just repackaging the upstream Kubewarden charts with new Rancher
version numbers (that prepend `100-`). All needed changes for Rancher
Charts must be present in upstream Kubewarden charts.
If, in the future, we would need functionality from the Rancher Packages
scripts, we will always have the possibility to add a new stage for it.

The Rancher charts & Rancher packages specification can be read from:
- [Rancher charts docs](https://rancher.com/docs/rancher/v2.6/en/helm-charts/creating-apps/#additional-files-for-rancher-charts)
- [Rancher chart dev docs](https://github.com/rancher/charts/blob/dev-v2.6/README.md)
- [Requirements and chart annotations docs](https://confluence.suse.com/pages/viewpage.action?spaceKey=EN&title=Feature+Charts+Helm+Requirements)
- [Example of superchart](https://github.com/rancher/charts/tree/dev-v2.6/packages/rancher-monitoring/rancher-monitoring/generated-changes/dependencies)

Modify our charts to meet those. This includes (but is not exhaustive to, as it
is a moving target):

- Set minimum required Rancher chart annotations:
  * `catalog.cattle.io/namespace`: should be postfixed with `-system` for UI
    filtering. When creating v2 of the chart, the namespace should be different
    than on v1, to handle upgrades/cleanup independently.
  * `catalog.cattle.io/release-name`: If unset, release name can be changed in UI.
  * `catalog.cattle.io/certified`
  * `catalog.cattle.io/certified`
  * `catalog.cattle.io/experimental`
  * `catalog.cattle.io/ui-component`
  * `catalog.cattle.io/display-name`
  * `catalog.cattle.io/os`
- Set `catalog.cattle.io/rancher-version` annotation as is required for
  user-facing charts.
- Provide `chart/appreadme.md`.
- Provide logo for the chart by settings `icon` in `Chart.yaml`.
- Rancher automatically creates a list of container images from charts for
  airgap. Adopt Rancher's `repository` and `tag` values in values.yml.
- Submit list of upstream images to be mirrored to
  https://github.com/rancher/image-mirror. For normal container images, this is
  no problem. For Wasm modules, they will not be supported by the Rancher
  DockerHub repository.
- Provide our own `serviceaccount`.
- Define k8s min/max version with `kubeVersion` in `Chart.yaml`.
- Add scheduling options at a pod (affinity) and node level
  (taints/tolerations/selectors).
- Provide `annotations.catalog.cattle.io/upstream-version`. This could be
  automatically bumped on release.
- Provide `questions.yaml` for defaults on Rancher Explorer UI.

The Kubewarden stack has the following dependencies:
- Designated main chart: `kubewarden-controller`. This will be the main charts
  to build a Rancher package from.
- Hard dependencies: 
  * CRDs: in `kubewarden-crds` chart. On the main Kubewarden chart
    (`kubewarden-controller`), set `catalog.cattle.io/auto-install:
    kubewarden-crds=match` that points to the right CRD version.
    This annotation accepts `match`, or a hardcoded version (e.g: `1.1.0`)
    We ought to set it to a hardcoded version, to be able to release patch
    versions.  of `kubewarden-controller` independently.
  * `cert-manager`: considered a precondition of Rancher Explorer. Rancher
    instructs users to install it prior to installing Rancher, so we can assume
    it is always present.
- Soft (optional) dependencies:
  * `grafana`, `kube-prometheus-stack`: provided by `rancher-monitoring` chart.
  * `jaeger-operator`: provided by `rancher-tracing` chart.
  * `open-telemetry/opentelemetry-operator`: not yet in Rancher's repository. We
    will need to submit it (possibly to
    https://github.com/rancher/partner-charts) and maintain.
  * `kubewarden-defaults`

  For the ones depending on CRDs (`kubewarden-defaults`,
    `opentelemetry-operator`, `jaeger-operator`), Rancher charts follow a 3 step
  process (this process is only for optional dependencies, see previous hard
  dependencies annotations):
  * Wrap the custom resource in a conditional that is tied to a values.yaml
    parameter.
  * Talk to the Rancher Explorer UI team to implement a solution and create a
  dashboard issue. Make them aware that if a certain CRD is defined we want to
  flip the new added value to true. If there is configuration available on that
  resource then it would be grayed out in the UI if the CRD is not available,
  and editable if the CRD is available.
  * Document this in our charts.
  
  For the ones not depending on CRDs (`grafana`, `prometheus`), we expect end
  users to deploy/reuse a chart for them and configure the endpoints themselves.

All of the modifications to our codebases will be carried in `rancher-X`
branches, where `X` is the tag being targeted.
They will be feature branches with parent being the commit tagged `X`. Using
these branches allows for easy rebases and cherry-picks, and documenting
needed changes per commit. 

We expect that all changes will be mergeable against `main`, but having the
branch around as a pointer provides separation of the Rancher vendored code,
which may be of no interest to upstream policy or Kubewarden chart authors, and
may coexist with other vendors.

The resulting charts from `rancher-X` will be used to build Rancher charts from
source by using the
[Package](https://github.com/rancher/charts/blob/dev-v2.6/docs/packages.md)
format in https://github.com/rancher/charts.
They will be submitted via a `packages/kubewarden/<kubewarden
chart>/package.yaml`, with
`package.yaml::commit` pointing to the relevant `rancher-X` branch.
This package will ideally contain only one patch: versions with a Rancher
version (`100-X.Y.Z` where `X.Y.Z` is the version of Kubewarden upstream
charts).

# Drawbacks
[drawbacks]: #drawbacks

# Alternatives
[alternatives]: #alternatives

Maintain all Rancher related changes in patches managed under
https://github.com/rancher/charts.  via `packages/kubewarden/<kubewarden
chart>/package.yaml` packages. This increases maintenance costs.

# Unresolved questions
[unresolved]: #unresolved-questions

While soft (optional) dependencies for Kubewarden charts are ok, they are
implemented directly in Rancher Explorer UI logic, as per Rancher policy. This
could be improved.

All needed images for the charts need to be mirrored in the Rancher DockerHub
repository, instead of being consumed from upstream. For normal container
images this is no problem, but not so for Wasm modules. We need to raise the
request to provide a Rancher OCI registry, use Kubewarden's upstream one, or
else.

We soft-depend on `open-telemetry/opentelemetry-operator` chart, which is not in
the Rancher repos. We need to understand who maintains these common charts and
how.
