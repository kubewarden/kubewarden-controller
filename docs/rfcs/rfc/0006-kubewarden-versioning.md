|              |                                                 |
|:-------------|:------------------------------------------------|
| Feature Name | Kubewarden versioning                           |
| Start Date   | Mar 3rd 2022                                    |
| Category     | Versioning                                      |
| RFC PR       | [PR4](https://github.com/kubewarden/rfc/pull/4) |

# Summary
[summary]: #summary

Kubewarden is composed of many core components that work together in
order to build the final product. This is a proposal to harmonize
Kubewarden versioning schema.

# Motivation
[motivation]: #motivation

Having a way to specify what version of Kubewarden is being installed
or executed would make it easier for the Kubewarden team to describe,
market and support Kubewarden (as in user support).

It would help users in understanding what version of Kubewarden they
are about to install or execute.

## Examples / User Stories
[examples]: #examples

### User story #1

> Users do not need to keep track of component versions and how they
> work together. They just need to care about running a specific
> Kubewarden version.

### User story #2

> Users are able to easily understand that a new version of Kubewarden
> is available, and that more than one component might be upgraded in
> order to move to the new Kubewarden version.

### User story #3

> A user has an issue with Kubewarden. Given its multiple component
> nature, we would like to know what was the Kubewarden version that
> got installed, and through what versions it was upgraded.

### User story #4

> As Kubewarden maintainers we want to define a version skew policy
> that is easy to be understood and implement.
> Something similar to what [Kubernetes does](https://kubernetes.io/releases/version-skew-policy/)
### User story #5

> As a user upgrading Kubewarden to a new version, I want to know if the new version introduces backward incompatible changes and behavior, so I can decide if to upgrade, and how. For example, if upgrading the helm charts in my cluster has backwards-incompatible changes, as I may be forced to redeploy from scratch, halt workloads of do manual tasks. Or if kwctl introduces backwards-incompatible changes, that would necessitate changes to my CI infrastructure.
# Detailed design
[design]: #detailed-design

## Many components, one experience

Kubewarden core components, which are exposed to the user are:

- Helm Charts
- Kubewarden Controller
- Policy Server
- kwctl

As a second dimension, there are also policies and their respective
SDK's. This proposal is going to ignore this dimension on purpose,
because Kubewarden runtime components (`policy-server` and `kwctl`)
should be compatible with policies previously built, even with older
language SDK's.

We want to have a single version for these "public" Kubewarden
components. This version is going to be expressed using
[Semantic Versioning](https://semver.org/).

The Kubewarden Controller, the Policy Server and kwctl components are going
to share the same *Major* and *Minor* version numbers. Each project is
going to have an independent *Patch* level number.

All the non-visible components of Kubewarden (e.g. the different
Rust libraries) and the policies are going to retain their
existing version numbers, release strategy and, generally speaking,
independence.

### Helm charts

Helm charts have two kind of version numbers:

* `version`: a SemVer 2 version specific to the helm chart
* `appVersion`: the version of the app that the chart contains

The helm charts will keep their own independence when it comes to
the `version` attribute.
On the other hand, the `appVersion` attribute
will always be set to the `<Major>.<Minor>` version of the
Kubewarden stack.

> See the official documentation about
[`Chart.yaml`](https://helm.sh/docs/topics/charts/#the-chartyaml-file)
for more information.

## Examples

This section provides clarity about how the proposal would work
using some concrete real-world scenarios.

### A new release Kubewarden takes place

A new version of Kubewarden stack has to be released. That can
happen because a new important feature/bugfix has been added,
because of marketing reasons,...

Let's assume:

* The current version of the Kubewarden stack is `0.5.3`
* The current version of the helm chart is `v0.10.3`

The new feature is not worth a major bump of the "unique kubewarden stack version",
hence we will perform a minor update.

We are going to tag `v0.6.0` of all these components and release them:

* Kubewarden Controller
* Policy Server
* kwctl

This will happen **regardless** of the changes done to these projects. For
example, kwctl is going to have a new release `v0.6.0` even if it didn't
have any commits since `v0.5.3` was tagged.

The Helm charts are updated in this way:

* The version of container images (Policy Server, Kubewarden
  Controller) are set to be `0.6.0`
* The chart `version` attribute is set to `v0.10.4` because no significant
  changed happened
* The `appVersion` attribute is set to `0.6.0`

### A patch is done to kwctl

A series of minor issues are found inside of kwctl. We decide to
tag a new release that includes these fixes.

The version of `kwctl` is updated from `0.6.0` to `0.6.1`.
No other releases are done

### A patch is done to Kubewarden Controller

A minor issue is fixed with Kubewarden Controller. We decide to
tag a new release that includes the fix.

The following actions are done:

* We tag a new release of kubewarden-controller: `0.6.1`
* We update the helm chart that makes use of this image:
  * We update the references of the image to ensure `0.6.1` is being pulled
  * We update the `version` number of the chart itself to be
    change from `0.10.4` to `0.10.5`.
    
    **Note:** we don't change the `appVersion` attribute

### A major security issue is found inside of Policy Server

A major security issue is found inside of Policy server.
Changes are done to both policy server and Kubewarden Controller.

We decide to release a new version of the whole stack, because of
the size of the changes and the impact. We will bump the
Kubewarden stack from `0.6.0` to `0.7.0`.

We proceed with the following actions:

* Tag a new release of Kubewarden Controller: `0.7.0`
* Tag a new release of Policy Server: `0.7.0`
* Tag a new release of kwctl: `0.7.0`. We do that even though
  no actual change has been done to kwctl
* helm chart:
  * Update all the references to the Kubewarden Controller and
    Policy Server images
  * Update `version`: this time the changes involve some updates to
    the helm chart itself. We deem this is worth a minor update.
    Because of that, the `version` goes from `0.10.5` to `0.11.0`
  * Update the `appVersion` to be `0.7.0`

### A bug is found inside of one of the helm charts

A small fix is done to one of the existing helm charts.

The version of the Kubewarden stack is **not** going to be changed.
Only the `version` inside of the patched helm chart is going to be
bumped.

# Drawbacks
[drawbacks]: #drawbacks

- There are times when the version of one of the components of
  the "public stack" is bumped even if no actual changes have
  been done to its source code.
- The global stack version does not make use of the `Patch`
  attribute of Semantic Versioning. That's because we want to
  leave some freedom to each component of the "public stack".

# Alternatives
[alternatives]: #alternatives

[This](https://github.com/kubewarden/kubewarden-controller/pull/182)
rejected proposal.

# Unresolved questions
[unresolved]: #unresolved-questions

None
