|              |                                 |
|:-------------|:--------------------------------|
| Feature Name | Kubewarden versioning           |
| Start Date   | Mar 3rd 2022                    |
| Category     | Versioning                      |
| RFC PR       | [fill this in after opening PR] |

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

> Users do not need to keep track of component versions and how they
> work together. They just need to care about running a specific
> Kubewarden version.

> Users are able to easily understand that a new version of Kubewarden
> is available, and that more than one component might be upgraded in
> order to move to the new Kubewarden version.

> A user has an issue with Kubewarden. Given its multiple component
> nature, we would like to know what was the Kubewarden version that
> got installed, and through what versions it was upgraded.

# Detailed design
[design]: #detailed-design

## Many components, one experience

Kubewarden core components, which are exposed to the user are:

- Helm Charts
- Kubewarden Controller
- Policy Server
- kwctl

As a second dimension, there are also policies and their respective
SDK's. This proposal is going to ignore this dimension in purpose,
because Kubewarden runtime components (`policy-server` and `kwctl`)
should be compatible with policies previously built, even with older
language SDK's.

### Public interfaces

Our public interfaces with users are as follows:

- Helm Charts
  - `values.yaml`
- Kubewarden Controller
  - CLI args
  - Custom Resource Definitions
    - Versioned
- Policy Server
  - CLI args
  - Configuration
    - sigstore related files
    - Usually handled by the Kubewarden Controller. Regardless we
      should treat this as public interface, given some users might
      run the Policy Server independent of the Kubewarden Controller,
      and might configure it with the configuration file.
- kwctl
  - CLI args
  - Configuration
    - `sources.yaml`
    - `docker.json`
    - sigstore related files

There is also the `waPC` contract between the `policy-evaluator`
(consumed by the Policy Server and kwctl) and Policies and SDK's.

## Kubewarden toplevel version

This proposal envisions using [`CalVer`](https://calver.org/) to
version the Kubewarden project.

Had Kubewarden be released today, it would be `Kubewarden
22.03`. This makes it trivial to understand how old your version of
Kubewarden is, and how much your installation is drifting from the
latest releases.

## Kubewarden component versions

Every component in Kubewarden might have its own versioning. The
Kubewarden maintainers are going to maintain a list of all releases.

This list of releases looks as follows:

```yaml
"22.03":
  - component: kubewarden-crds-chart
    version: 0.1.1
  - component: kubewarden-controller-chart
    version: 0.3.6
  - component: kubewarden-controller
    version: v0.4.5
  - component: policy-server
    version: v0.2.6
  - component: kwctl
    version: v0.2.5
"22.05":
  - component: kubewarden-crds-chart
    version: 0.2.0
  - component: kubewarden-controller-chart
    version: 0.4.0
  - component: kubewarden-controller
    version: v0.4.8
  - component: policy-server
    version: v0.3.0
  - component: kwctl
    version: v0.3.1
...
```

As more components are relevant they can be added to the list as time
grows.

This map allows us to generate documentation and a single source of
truth to refer to when a user has a problem, or when we are debugging
an issue. It helps to understand if any component has drifted from the
version we are expecting.

The helm chart will be responsible of storing the "Kubewarden version"
in a resource, like a ConfigMap. So it's easy to inspect it and
understand what "Kubewarden version" a cluster is running.

Had other external components such as `kwctl` need to synchronize with
the cluster, they can inspect this ConfigMap and realize if they are
compatible with the running version of Kubewarden on the cluster they
are connecting to.

# Drawbacks
[drawbacks]: #drawbacks

- It's not a very common versioning scheme. I would consider reading
  ["When to use
  CalVer"](https://calver.org/#when-to-use-calver). Although
  Kubewarden does not have a "large" scope, it's to some extent
  "constantly changing", and this constant change would imply
  harmonizing versions of all components continuously.

# Alternatives
[alternatives]: #alternatives

## Have a regular Kubewarden toplevel version

Having a regular --even semver based-- version on the toplevel project
seems like an artificial construct. What is the meaning of patchlevel
release in this case? What is Kubewarden 1.2.3 vs 1.2.4?

Thus, ignoring patchlevel (e.g. just keeping 1.2 vs 1.3 vs 1.4, or
even 1 vs 2 vs 3) is an option. But then, if it's just meaningless
numbers, why not make the toplevel number meaningful, referring to the
date when the project was released. This brings instant information to
the user as opposed to version numbers.

## Sync all component versions

Given the nature of multiple components of the Kubewarden projects,
scattered across different repositories, closely related to each
other, enforcing a single synced version on all of them seem
artificial and heavily increases releasing efforts, given a problem or
feature in on one component forces to tag and release the rest of the
components.

# Unresolved questions
[unresolved]: #unresolved-questions

- Should day versions be included in the toplevel map?

    To make things even easier, versions might start with
    YEAR.MONTH. If there is the need to make a second global release
    during the same month, then a day is appended: YEAR.MONTH.DAY1. If
    a third release is needed during that month: YEAR.MONTH.DAY2.

    This makes it easier for maintainability of upgrades and is easier
    to describe what should the upgrade path be if there is the
    necessity of forcefully sequence upgrades in a certain order.

- Should complete versions of components (MAJOR.MINOR.PATCH) be
  referenced by the versions map as the example shows?

    The alternative would be that we use MAJOR.MINOR, and let PATCH be
    automatically upgradeable (e.g. through the helm-chart, by releasing
    patchlevel versions of the helm-chart that only bump pathlevel
    versions of kubewarden-controller or policy-server).

    This opens the door to more "kubwarden version" -> "component
    version" combinations, thus, making things harder to support.
