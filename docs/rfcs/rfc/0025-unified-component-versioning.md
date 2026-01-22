|              |                                                 |
| :----------- | :---------------------------------------------- |
| Feature Name | Unified component versioning                    |
| Start Date   | January 22nd, 2026                              |
| Category     | Versioning                                      |
| RFC PR       | [PR](https://github.com/kubewarden/rfc/pull/53) |
| State        | **ACCEPTED**                                    |

# Summary

[summary]: #summary

This RFC supersedes [RFC 0007](0007-kubewarden-versioning.md) to align with the architectural change of consolidating all Kubewarden admission controller components into a single Git repository.
All core components will now share the same version number and be released together.

# Motivation

[motivation]: #motivation

With all Kubewarden Admission Controller components now residing in the same Git repository, maintaining separate versioning schemes adds unnecessary complexity. A unified versioning strategy will:

- Simplify the release process
- Reduce confusion for users and maintainers
- Ensure all components are tested and validated together
- Make bug reporting and troubleshooting more straightforward

See [RFC 0007](0007-kubewarden-versioning.md) for additional background and context.

## User Stories

[userstories]: #userstories

### User story #1

As a user, I want a single version number for all Kubewarden Admission Controller components so I can easily understand and upgrade the entire system without confusion.

### User story #2

As a maintainer, when a user reports an issue, I want to know the exact version of all components by asking for a single version number.

### User story #3

As a user upgrading Kubewarden Admission Controller, I want to know if the new version introduces backward incompatible changes so I can plan my upgrade accordingly.

# Detailed design

[design]: #detailed-design

## Unified versioning

All Kubernetes components of Kubewarden Admission Controller will share the same version, following [Semantic Versioning](https://semver.org/):

- Controller
- Policy Server
- Audit Scanner
- kwctl
- CRDs

All components will be tagged and released together using the same `<Major>.<Minor>.<Patch>` version number, even if some components have not changed since the previous release.

Policies and their SDKs remain independent and are not included in this versioning scheme, as runtime components maintain backward compatibility with policies built using older SDKs.

## Helm Charts

Helm charts maintain two version fields:

- `version`: SemVer 2 version specific to the Helm chart
- `appVersion`: version of the Kubewarden stack the chart deploys

When a new minor version of the Kubewarden Admisison Controller is released, the Helm chart `version` will receive a minor bump.
Additional chart-only changes may also trigger version bumps independently.
The Helm chart `version` can also receive `major` bumps when breaking changes are introduced.

The `appVersion` will always match the Kubewarden Admission Controller stack version.

See the official [Chart.yaml documentation](https://helm.sh/docs/topics/charts/#the-chartyaml-file) for more details.

## Examples

[examples]: #examples

### A new release of Kubewarden

Assumptions:

- Current Kubewarden stack version: `1.5.0`
- Current Helm chart version: `2.10.3`

Actions:

- Tag all components (Controller, Policy Server, kwctl, Audit Scanner) as `1.6.0`
- Update Helm charts:
  - Set container image versions to `1.6.0`
  - Bump chart `version` to `2.11.0`
  - Set `appVersion` to `1.6.0`

### A patch release

A bug is fixed in one or more components.

Assumptions:

- Current Kubewarden stack version: `1.6.0`
- Current Helm chart version: `2.11.0`

Actions:

- Tag all components as `1.6.1`, even those without changes
- Update Helm charts:
  - Update container image references to `1.6.1`
  - Bump chart `version` to `2.11.1`
  - Set `appVersion` to `1.6.1`

### A breaking change

A breaking change is introduced (e.g., CRD field removal, configuration format change).

Actions:

- Bump to next major or minor version (e.g., `1.6.0` → `2.0.0` or `1.7.0`)
- Tag all components with the new version
- Update Helm charts:
  - Update container image references
  - Bump chart `version` (major or minor bump)
  - Set `appVersion` to the new version

### Helm chart-only change

A fix is made only to the Helm chart with no component changes.

Actions:

- Bump only the Helm chart `version` (patch or minor)
- Leave `appVersion` unchanged

# Drawbacks

[drawbacks]: #drawbacks

- Components are tagged with new versions even when unchanged
- Requires coordinated releases across all components
- Cannot patch individual components independently

# Alternatives

[alternatives]: #alternatives

## Maintain independent versioning

Continue with the approach from RFC 0007 where components share only major and minor versions.

Impact: More complex version management; doesn't leverage the benefits of the monorepo structure.

# Unresolved questions

[unresolved]: #unresolved-questions

- Release automation strategy to minimize manual errors
- Frequency of releases and balance with automation investment
