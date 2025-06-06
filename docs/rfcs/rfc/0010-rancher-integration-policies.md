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

For policies owned by the Kubewarden team this RFC proposes building a catalog,
using the [Rancher's Helm charts catalog system](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/helm-charts-in-rancher).

For 3rd party policies not owned by the Kubewarden team,
this RFC proposes using the Artifact Hub API to poll for the metadata stored in
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
3. As a user, I want to install 3rd party Kubewarden policies via the Rancher
   Explorer UI.
4. As a Kubewarden developer, I want to release a new Kubewarden policy so
   it can be installed via the Rancher Explorer UI.
5. As a 3rd party developer, I want to release a policy on Artifact Hub so it can
   be discovered and installed via the Rancher Explorer UI.
6. As a user, I want to install Kubewarden policies via Rancher Explorer UI, in
   an airgapped system.

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

### Policy catalog

Once released, the policies are consumed by following the process listed in
[RFC-9, Rancher integration of Kubewarden
charts](./0009-rancher-integration-charts.md) with the following changes.

All policies will be listed in a new repository:  
[https://github.com/kubewarden/policy-catalog](https://github.com/kubewarden/policy-catalog).  
This repository will act as a Helm chart repository, published via GitHub Pages.

Each policy release will generate `Chart.yaml`, `values.yaml` files that
include the metadata required by the Rancher UI.
Thess file will be placed at `charts/<policy-name>/Chart.yaml` and
`charts/<policy-name>/values.yaml`.

If the original policy contains a `questions-ui.yml` file, it will be copied to `charts/policy-name/questions.yaml`.
The `LICENSE` and `README.md` files will also be copied into the chart directory.

This is not a functional Helm chart, as it doesn't include any templates.
It only provides the metadata needed by the Rancher Explorer UI, making use of the existing Helm chart repository structure.

You can refer to the [Rancher source code](https://github.com/rancher/rancher/blob/794ebe98840e64e47664df2e28d67e76cbc37bf6/pkg/api/steve/catalog/types/rest.go#L50-L56) for more details.

This setup also helps avoid hitting the Artifact Hub API rate limits.
As the number of policies grows, so do the API calls, and we were starting to reach those limits quickly.

### Chart.yaml generation

For each policy release the `Chart.yaml` file will be generated or updated from the `artifacthub-pkg.yml` and `artifacthub-repo.yml` files present in the policy repository.

The `name`, `version`, `description`, `keywords` fields will be taken from the `artifacthub-pkg.yml` file.

All the annotations present in `artifacthub-pkg.yml` will be copied to the `Chart.yaml` file.
Addtionally, the following annotations will be added to the `Chart.yaml` file:

- `artifacthub.io/repository`: The name of the Artifact Hub repository where the policy is published. This will be fetched by querying the Artifact Hub API using the `repositoryID` present in the `artifacthub-repo.yml` file.
- `kubewarden/displayName`: The display name of the policy. This is obtained by the `displayName` field in the `artifacthub-pkg.yml` file.
- `catalog.cattle.io/ui-component`: Always set to `kubewarden`.
- `catalog.cattle.io/hidden`: Always set to `true`.
- `catalog.cattle.io/type`: Always set to `kubewarden-policy`.

The following annotations are marked as deprecated, and substituted by the
`values.yaml` file:

- `kubewarden/registry`: The OCI registry where the policy is published. This is obtained by the `containesImages` field in the `artifacthub-pkg.yml` file.
- `kubewarden/repository`: The OCI repository where the policy is published. This is obtained by the `containesImages` field in the `artifacthub-pkg.yml` file.
- `kubewarden/tag`: The OCI tag where the policy is published. This is obtained by the `containesImages` field in the `artifacthub-pkg.yml` file.

The `kubewarden/questions-ui` annotation will be not set in the `Chart.yaml` file, since the `questions.yaml` file will be copied to the chart directory.

Example of a `Chart.yaml` file:

```yaml
annotations:
  artifacthub.io/repository: allowed-fsgroups-psp-policy
  catalog.cattle.io/hidden: "true"
  catalog.cattle.io/type: kubewarden-policy
  catalog.cattle.io/ui-component: kubewarden
  kubewarden/displayName: Allowed Fs Groups PSP
  kubewarden/mutation: "true"
  kubewarden/registry: ghcr.io # deprecated, moved to values
  kubewarden/repository: kubewarden/policies/allowed-fsgroups-psp # deprecated, moved to values
  kubewarden/resources: Pod
  kubewarden/rules: |
    - apiGroups:
      - ''
      apiVersions:
      - v1
      resources:
      - pods
      operations:
      - CREATE
      - UPDATE
  kubewarden/tag: v0.1.10 # deprecated, moved to values
appVersion: 0.1.10
description:
  Replacement for the Kubernetes Pod Security Policy that controls the
  usage of fsGroups in the pod security context
home: https://github.com/kubewarden/allowed-fsgroups-psp-policy
keywords:
  - psp
  - container
  - runtime
name: allowed-fsgroups-psp
sources:
  - ghcr.io/kubewarden/policies/allowed-fsgroups-psp:v0.1.10
version: 0.1.10
```

### values.yaml generation

The `values.yaml` file will be generated or updated from the
`artifacthub-pkg.yml` and `artifacthub-repo.yml` files present in the policy
repository.

The values file contains the needed metadata to know from where to obtain the
OCI artifact from, and at the same time allows users to overwrite this values
and save them in the deployed Helm release. It also follows the Rancher
convention of `global.cattle.systemDefaultRegistry` values.

This allows users, via the Kubewarden UI, to overwrite the registry and
repository. This enables airgap deployments and the usage of registry mirrors.

Example of a `values.yaml` file:

```yaml
global:
  cattle:
    systemDefaultRegistry: ghcr.io
module:
  repository: kubewarden/policies/sysctl-psp
  tag: v1.0.2
```

### Policy catalog release flow

Every time a policy is released, the `policy-catalog` repository will be updated.
This will be done by a GitHub Action workflow in the `policy-catalog`, triggered by the policy release job via repository dispatch.

The workflow will:

- Check out the `main` branch of the policy repository at the given tag and copy the `README.md`, `LICENSE`, and `questions.yaml` files to the chart directory.
- Check out the `artifacthub` branch of the policy repository at the given tag.
- Generate the `Chart.yaml` file from the `artifacthub-pkg.yml` and `artifacthub-repo.yml` files.
- Copy the `Chart.yaml` file to the chart directory.
- Create a PR against the `main` branch of the `policy-catalog` repository with the changes.

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
