|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Rancher integration of Kubewarden Policies  |
| Start Date   | 2022-08-22                       |
| Category     | Development                      |
| RFC PR       | https://github.com/kubewarden/rfc/pull/11  |
| State        | **ACCEPTED**                     |


# Summary
[summary]: #summary

This RFC explains how the Kubewarden policies, either owned by the Kubewarden
team or 3rd party ones, can be integrated in Rancher Explorer.

For policies owned by the Kubewarden team  it proposes a development workflow
using git branches and automation. The needed Rancher Helm charts and Rancher
Packages artifacts metadata is tracked in a separate orphan branch for each
artifact's repo, and submitted to https://github.com/rancher/charts.

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

2. As a user, I want to install one Kubewarden policy owned by the
   Kubewarden/Rancher team via Rancher Explorer UI.
3. As a user, I want to install several Kubewarden policies owned by the
   Kubewarden/Rancher team via Rancher Explorer UI.
4. As a user, I want to install 3rd party Kubewarden policies via Rancher
   Explorer UI.
5. As a Kubewarden developer, I want to release a new Kubewarden chart/policy so
   it can be installed via Rancher Explorer UI.
6. As a 3rd party developer, I want to release a policy on Artifact Hub so it can
   be installed via Rancher Explorer UI.

# Detailed design
[design]: #detailed-design

## For policies owned by the Kubewarden team

Follow the process listed in [RFC-9, Rancher integration of Kubewarden
charts](./0009-rancher-integration-charts.md).

Carry the Helm chart code for the policy in a `rancher-X` orphan branch, where `X`
is the release tag of the policy being targeted.
Using these branches allows for easy rebases and cherry-picks, and documentating
needed changes per commit. This also separates the Rancher vendored code, which
may be of no interest to policy authors, and may coexist with other vendors.

The resulting charts from `rancher-X` will not be served and released by us, but
used to build Rancher charts from source by using the
[Package](https://github.com/rancher/charts/blob/dev-v2.6/docs/packages.md)
format in https://github.com/rancher/charts.
They will be submitted via a `packages/kubewarden/<policy>.package.yaml`, with
`package.yaml::commit` pointing to the relevant `rancher-X` branch.

For policy bundles, they can be in their own repository containing the chart
and modifications in a `rancher-X` branch (e.g: see `kubewarden-defaults`).

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

Artifacts owned by the Kubewarden team are also present in Artifact Hub, hence
to avoid listing them twice, they should be skipped if `provider` of the package
is `kubewarden`, and/or the URL starts with `https://github.com/kubewarden/`.

# Drawbacks
[drawbacks]: #drawbacks

## For policies owned by the Kubewarden team

Needing new Helm charts to ship policies owned by the Kubewarden team.

A pull request bot needs to be created to make the submissions to
https://github.com/rancher/charts, and we will need external approvals for
merging.

## For 3rd party policies

Using the provided Artifact Hub API, given that it doesn't have pagination and
one needs to query for each package independently, will be inefficient. A cache
could be implemented.

Obtaining the policies via the API is still missing:
- Metadata not present in `policy/artifacthub-pkg.yml` yet present in
  `policy/metadata.yml`, namely the array of `rules`.
- `question.yml` information. Not a problem per se, as 3rd party policies would
  not need Rancher integration.

Airgap installations wouldn't be possible.

# Alternatives
[alternatives]: #alternatives

## A. Using the metadata stored in the custom section of Wasm modules

It could be possible to save the `questions.yml` metadata in the metadata
annotations of `annotated-policy.wasm` themselves (the custom section of the
Wasm module containing raw data, for us with the name
`KUBEWARDEN_CUSTOM_SECTION_METADATA`).

With this, annotated policies will contain almost all metadata needed.
Information about if the policy is signed couldn't be included there by
definition.

Then, Rancher Explorer frontend could make use of a client for OCI registries
(such as [oci-registry-js](https://www.npmjs.com/package/oci-registry-js) or a
wasm-compiled Rust library for example), to pull and cache each Wasm module.
With [`WebAssembly.Module.customSections()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WebAssembly/Module/customSections)
it would be possible to extract all the metadata from the annotations of the
policy.

This would mean to pull hundreds of megabytes, as it will download the Wasm
module of the policies, regardless of pagination and caching.

## B. Storing policy metadata in the OCI registry

Same as alternative (A), but storing the policies' metadata in the OCI registry
either under:
- A new layer, with `config.mediaType` [creating an artifact type
`application/vnd.oci.yaml-sample.config.v3+yaml`](https://github.com/opencontainers/artifacts/blob/main/artifact-authors.md#defining-a-unique-artifact-type).
  This means pulling layers, and possibly uncompressing them.
- Or in `manifest.config` (https://github.com/opencontainers/artifacts/blob/main/artifact-authors.md#optional-defining-config-schema)

It would then be retrieved with an OCI registry client. This would be more
efficient than pulling full Wasm modules for all policies as in (A).

Airgap installations would consist on mirroring the registry.

A drawback could be finding OCI registry clients that can deal with these
formats.


# Unresolved questions
[unresolved]: #unresolved-questions

Alternative (B) looks the most promising, but more investigation on a
frontend-capable OCI registry client needs to be done.
