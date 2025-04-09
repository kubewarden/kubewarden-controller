|              |                                            |
| :----------- | :----------------------------------------- |
| Feature Name | Rancher integration of Kubewarden Policies |
| Start Date   | 2022-08-22                                 |
| Category     | Development                                |
| RFC PR       | https://github.com/kubewarden/rfc/pull/11  |
| State        | **ACCEPTED**                               |

# Summary

[summary]: #summary

This RFC explains how the Kubewarden policies, either owned by the Kubewarden
team or 3rd party ones, can be integrated in Rancher Explorer.

For policies owned by the Kubewarden team it proposes building Rancher Helm charts
that will be published under https://github.com/rancher/charts.

For 3rd party policies not owned by the Kubewarden team,
it proposes using the Artifact Hub API to poll for the metadata stored in
`policy/artifacthub-pkg.yml`.

# Motivation

[motivation]: #motivation

Problems to solve:

- Obtain the list of available policies regardless of where they come from, and
  their metadata to show in Rancher Explorer UI.
- Allow for groups of policies to be installed.
- Implement it efficiently and with low development maintenance costs.
- Allow for airgap installations.

## Examples / User Stories

[examples]: #examples

1. As a user, I want to install one Kubewarden policy owned by the
   Kubewarden/Rancher team via Rancher Explorer UI.
2. As a Kubewarden developer, I want to allow users to deploy a collection of related policies
   in a simple way. For example: "PSP best of", "Security best practices",...
3. As a user, I want to install 3rd party Kubewarden policies via Rancher
   Explorer UI.
4. As a Kubewarden developer, I want to release a new Kubewarden chart/policy so
   it can be installed via Rancher Explorer UI.
5. As a 3rd party developer, I want to release a policy on Artifact Hub so it can
   be discovered and installed via Rancher Explorer UI.

# Detailed design

[design]: #detailed-design

## For 3rd party artifacts

Use the provided [artifacthub.io public API](https://artifacthub.io/docs/api/).
Currently, the Artifact Hub API provides [`GET
/packages/search`](https://artifacthub.io/docs/api/#/Packages/searchPackages),
where one can set the `repository kind` to `Kubewarden policies`. With this call
one can obtain the list of Kubewarden policies. One would then query for each of
the policies with [GET
/packages/kubewarden/{repoName}/{packageName}](https://artifacthub.io/docs/api/#/Packages/getKubewardenPoliciesDetails),
and obtain its `name`, `version`, `signed` status, and `data/kubewarden-*`
information.

Artifacts owned by the Kubewarden team are also present in Artifact Hub. Still,
they have different provenance, therefore, different support assurances. Hence,
they should be able to coexist.

## For policies owned by the Kubewarden team

### Building and releasing policy Wasm modules

The policies's Wasm modules are built, pushed to ghcr.io, and released via a
GitHub release. The process is as follows:

1. The policy has an annotation `io.kubewarden.policy.version` in their
   `metadata.yml` that specifies their version in semver format.
2. The policy has a GH workflow, `open-release-pr`, that triggers monthly. This
   workflow consumes a reusable workflow with the same name from
   github.com/kubewarden/github-actions >= @v4.4.0. The reusable workflow uses updatecli
   to detect changes since last tag, and if there's some, it bumps all needed
   metadata of the policy (the `io.kubewarden.policy.version` in `metadata.yml`,
   `Cargo.{toml, lock}` if needed, etc), commits those changes to a branch
   named `updatecli_main_release_pr`, and opens a PR against the policy repo.
   It obtains the prospective version to use for bumping the metadata from the latest
   GitHub draft release _title_ (e.g: "Release v1.2.0"), which is created by
   release-drafter. Release-drafter keeps the title up to date with bumps by
   evaluating conventional commits.
   The PR has a label `TRIGGER-RELEASE`.
3. Kubewarden devs review the PR and merge it.
4. The policy has a second GH workflow, `release-tag`, that triggers when a PR is merged.
   This workflow consumes a reusable workflow with the same name from
   github.com/kubewarden/github-actions >= @v4.4.0. The reusable workflow checks
   if the merged PR that triggered it contains a label `TRIGGER-RELEASE`. If it
   does, it creates a git tag matching the latest version in
   `io.kubewarden.policy-version` and pushes the tag, and deletes the
   `updatecli_main_release_pr` branch. This will trigger the job that builds and
   releases the policy in GitHub releases.

The only action to be taken by Kubewarden devs is to merge the automated PR
that bumps the metadata of the policy. The reviewers can amend the PR, or
can edit the GitHub draft Release title by hand, close the PR, delete its
branch, and dispatch the PR job manually again.

### Policy distribution

Once released, the policies are consumed by following the process listed in
[RFC-9, Rancher integration of Kubewarden
charts](./0009-rancher-integration-charts.md) with the following changes.

Submit all Helm charts of the policies to a new repository,
https://github.com/kubewarden/policy-charts, under a `charts/policies/` folder. This
repository will contain similar CI and scripts as the kubewarden/helm-charts
repository. The resulting policy Helm charts will get shipped into a separate
HTTPs Helm repository along with an OCI repository in ghcr.io.

Even if the charts will not be publicized to users, the repository can be consumed
in Rancher UI (using git URL and branch) for testing the chart itself.

For policy bundles, they can be in a new chart, either in this new
`kubewarden/policy-charts` or in `kubewarden/helm-charts`.

Inclusion into rancher/charts has been discarded given:

- We don't want to overload existing repos with hundreds of policies, for good UX
- We want to sign and continue with SLSA support
- The submission process to rancher/charts is complicated

### Chart annotations

The policies will have Chart.yaml annotations, as these are replicated in the
index.yaml of the Helm chart HTTPs repository.

For easiness on automating the creation and maintenance of the policy Helm
charts, we will mirror the metadata.yml annotations into the Helm chart
annotations instead of taking them from artifacthub-pkg.yml. This simplifies
creating charts from policies that are not slated to be released to ArtifactHub.

The following Kubewarden policy annotations in `metadata.yml` must be
replicated as-is in the Helm chart annotations in `Chart.yaml`:

- `io.artifacthub.displayName`
- `io.artifacthub.resources`
- `io.kubewarden.policy.description`
- `io.artifacthub.keywords`
- `io.kubewarden.policy.source`: Used for providing the link to the changelog.
- `io.kubewarden.policy.severity`: Used in the resulting template.yml.
- `io.kubewarden.policy.category`: Used in the resulting template.yml.

It is valid to just duplicate all annotations present in the `metadata.yml` of
the policy in question, for simplicity and futureproofing.

The following Helm Chart annotations are constructed from the `metadata.yml`.
The share the same key as their analogous on `artifacthub-pkg.yml` (since they
are mirroring what is expected by the ArtifactHub API), but are not taken from
there.

- `kubewarden/mutation`: `'true'` or `'false'`. Value of metadata.yml `mutating` value.
- `kubewarden/contextAwareResources`: Value of `metadata.yml`
  `contextAwareResources`. If present, specifies a context aware policy. It is a
  free multiline string containing an array of apiVersion kind objects
  ([example](https://github.com/kubewarden/unique-ingress-policy/blob/7cc3136a57df1fec821714523cf9ebe215d70895/artifacthub-pkg.yml#L42-L44)).

The following Rancher Helm chart annotations must be present:

- `catalog.cattle.io/certified`: rancher
- `catalog.cattle.io/ui-component` to `kubewarden`: This is added for custom UI deployment of a chart
- `catalog.cattle.io/os` to `linux`.
- `catalog.cattle.io/permits-os` to `linux,windows`
- `catalog.cattle.io/upstream-version` to `"<version of policy chart>"`: The version
  of the upstream chart or app. It prevents the unexpected "downgrade" when
  upgrading an installed chart that uses our 100.x.x+upVersion version schema.
- `catalog.cattle.io/ui-component: kubewarden`. Added for custom UI deployment of a chart.
- `catalog.cattle.io/hidden` to `"true"`.
- `catalog.cattle.io/type` to a new type, `kubewarden-policy`.
- `catalog.cattle.io/requires-gvr: "policyservers.policies.kubewarden.io/v1"`.
  This ensures we don't try to apply the policy template for Kubewarden's CR if
  we don't have the CRDs or the controller (which auto-installs the CRDs)
  present.

And the following must be missing:

- `catalog.cattle.io/scope`. Given that we are setting `catalog.cattle.io/hidden`
  to true, it is not relevant.

### Chart values

The `values.yaml` contain the needed fields, but at the same time must have the
same UX as the usual Kubewarden charts. We must expect the following to have
the same schema for all policies:

```yaml
# values.yaml
global: # global to all policies and charts
  cattle:
    systemDefaultRegistry: ghcr.io
module:
  repository: "kubewarden/policies/allow-privilege-escalation-psp" # not in spec.module as it doesn't include the registry
  tag: "v0.1.11"
clusterScoped: true # for ClusterAdmissionPolicy, or AdmissionPolicy
spec:
  mode: "protect"
  mutating: true # only present if it's true
  rules:
    # array as in the CRD spec
  settings:
    # either well formed YAML or multiline string depending on policy
```

For `spec.settings`, depending on the Helm chart it may be a well formed YAML
object or a multiline string, since the CRD defines it as a [free form
object](https://docs.kubewarden.io/reference/CRDs#policyspec).

For `spec.contextAwareResources`, it will be hardcoded on the policy chart template.

Only those values that are actually configurable should be in values.yml and questions.yml.
For example, if a policy is non mutating, it should not to have a
`spec.mutating: false` in the values.yml nor questions.yml.

### Chart template

The `templates/policy.yaml` will match the policy templates shipped in the
`kubewarden-defaults` Helm chart.

- The `spec.module` will be constructed by appending
  `.Values.global.cattle.systemDefaultRegistry` and `.Values.module.repository`.
- The `metadata.annotations` for severity and category will be obtained from
  the policy metadata.yml annotations `io.kubewarden.policy.severity` and
  `io.kubewarden.policy.category`.

As an example:

```
---
apiVersion: policies.kubewarden.io/v1
{{- if eq .Values.clusterScoped true }}
kind: ClusterAdmissionPolicy
{{- else }}
kind: AdmissionPolicy
{{- end }}
metadata:
  labels:
    app.kubernetes.io/component: policy
  annotations:
    io.kubewarden.policy.severity: {{ index .Chart.Annotations "io.kubewarden.policy.severity" | quote }}
    io.kubewarden.policy.category: {{ index .Chart.Annotations "io.kubewarden.policy.category" | quote }}
  name: {{ .Release.Name }} # allows for deploying the same policy several times with different configs
  {{- if eq .Values.clusterScoped false }}
  namespace: {{ .Release.namespace }}
  {{- end }}
spec:
  module: '{{ .Values.module.repository }}:{{ .Values.module.tag }}'
  mode: {{ .Values.spec.mode }}
  {{- if eq (index .Chart.Annotations "kubewarden/mutation") "false" }}
  mutating: false # policy doesn't support mutation
  {{- else }}
  mutating: {{ .Values.spec.mutating }}
  {{- end }}
  contextAwareResources: <array of GVK from metadata.yml::contextAwareResources> # optional
  rules:
    {{- toYaml .Values.spec.rules | nindent 4 }}
  settings: # either YAML object or multiline string
  # other optional fields, such as executionMode, backgroundAudit, etc
```

### Tests and CI

We will reuse the CI from kubewarden/helm-charts for bash. We will amend the
already present helm unit tests (with `helm unittest`) to provide a simple test
on rendering the templates with some expected variations of the `values.yml`.

### Chart UI questions

As listed in RFC-9, the chart will ship a `questions.yaml` whose content is
just the already existing `questions-ui.yml` that is being used for
`artifacthub-pkg.yml`.

### Chart changelog

Each policy chart will ship a `CHANGELOG.md` file just like the usual Kubewarden charts do.
The contents of this file are created via the `make generate-changelog-file` target,
which use the URL listed in the metadata.yml annotation `io.kubewarden.policy.source`.

### Chart artifacts

The policy Helm charts must contain a `policylist.txt` file in the shipped tgz chart,
analogous to usual Kubewarden Helm charts. For that we must retouch the `make
generate-policies-file` target and the `extract-policies.sh` script. This
enforces SLSA and helps in verification of signed Helm charts.

### Updating the Helm policy chart repository

To create a new policy chart from a newly released policy version, one needs to
uniquely relate the policy and the policy chart. This is regardless of the
policy being a normal one or a monorepo one.

For that, one needs the name of the policy.

Once a new policy release happens,

# Drawbacks

[drawbacks]: #drawbacks

## For policies owned by the Kubewarden team

Needing new Helm charts to ship policies owned by the Kubewarden team.

## For 3rd party policies

Using the provided Artifact Hub API, given that it doesn't have pagination and
one needs to query for each package independently, will be inefficient. A cache
could be implemented.

The following metadata is not obtainable without reading the Wasm binary right
now, therefore should be added to `policy/artifacthub-pkg.yml`:

- Metadata not present in `policy/artifacthub-pkg.yml` yet present in
  `policy/metadata.yml`, namely the array of `rules`.
- `questions.yml` information. Not a problem per se, as 3rd party policies would
  not need Rancher integration.

Airgap installations need to catch the Artifact Hub metadata somehow.

# Alternatives

[alternatives]: #alternatives

## A. Using the metadata stored in the custom section of Wasm modules

It could be possible to save the `questions.yml` metadata in the metadata
annotations of `annotated-policy.wasm` themselves (the custom section of the
Wasm module containing raw data, for us with the name
`KUBEWARDEN_CUSTOM_SECTION_METADATA`). `rules` metadata is present there
already.

With this, annotated policies will contain almost all metadata needed.
Information about if the policy is signed couldn't be included there by
definition.

Then, Rancher Explorer could make use of a client for OCI registries
(such as [oci-registry-js](https://www.npmjs.com/package/oci-registry-js) or a
wasm-compiled Rust library for example), to pull and cache each Wasm module.
With [`WebAssembly.Module.customSections()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WebAssembly/Module/customSections)
it would be possible to extract all the metadata from the annotations of the
policy.

This would mean to pull hundreds of megabytes, as it will download the Wasm
module of the policies, regardless of pagination and caching.

Airgap installations would consist on mirroring the OCI registry (since metadata
in stored in the Wasm modules).

## B. Storing policy metadata in the OCI registry

Same as alternative (A), but storing the policies' metadata in the OCI registry
either under:

- A new layer, with `config.mediaType` [creating an artifact type
  `application/vnd.oci.yaml-sample.config.v3+yaml`](https://github.com/opencontainers/artifacts/blob/main/artifact-authors.md#defining-a-unique-artifact-type).
  This means pulling layers, and possibly uncompressing them.
- Or in `manifest.config`
  (https://github.com/opencontainers/artifacts/blob/main/artifact-authors.md#optional-defining-config-schema).
  Which is not compressed, and whose checksum matches the checksum of the
  uncompressed contents of the `manifest.config`.

It would then be retrieved with an OCI registry client. This would be more
efficient than pulling full Wasm modules for all policies as in (A).

This means policies would have the metadata saved in both:

- Wasm module, as of today. Used by `kwctl`, `policy-server`.
- OCI registry `manifest.config`.

This would mean that policy-related metadata can be dropped from
`policy/artifacthub-pkg.yml`, which should only contain things related to
Artifact Hub.

Airgap installations would consist on mirroring the OCI registry.
Rancher airgap works by providing a list of images to be mirrored, and
instructions for using a private registry. We would need to instruct Kubewarden
users to use an additional OCI private registry, and an OCI-capable client for
performing the mirroring.

This alternative provides the same implementation for both kubewarden-owner
policies, Rancher-mirrored policies, and 3rd party policies. Just serve each of
them on their respective OCI registries.

A drawback could be finding frontend-capable OCI registry clients that can deal
with these formats, and can authenticate against private registries too.

# Unresolved questions

[unresolved]: #unresolved-questions

As in RFC-9, all needed images for the charts need to be mirrored in the Rancher
DockerHub repository, instead of being consumed from upstream. Since policies
are Wasm modules, we need to raise the request to provide a Rancher OCI
registry, use Kubewarden's upstream one, or else.
