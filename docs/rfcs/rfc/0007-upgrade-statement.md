|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Upgrade Statement                |
| Start Date   | 05/23/2022                       |
| Category     | updates and versioning           |
| RFC PR       | https://github.com/kubewarden/rfc/pull/6  |
| State        | **ACCEPTED**                  |


# Summary
[summary]: #summary

This RFC proposes how the upgrade of the Kuberwarden stack will work and how to do it.

# Motivation
[motivation]: #motivation

Kubewarden is reaching the v1.0 milestone and we need to define a upgrade process
to users and for the development team to follow. With it, users will be able
to plan when and how to upgrade their Kuberwarden stack. And the Kuberwarden developers
will be able to define when and how ship new features and fixes.

## Examples / User Stories
[examples]: #examples

As Kubewarden user, I want to know, among all Kubewarden components, what are the
compatible versions.

As Kubewarden user, I want to know the upgrade path of the Kuberwarden components.

As a Kubewarden developer, I want to know what is the upgrade path between
Kubewarden versions, so that I can perform proper QA before releasing a new
version of the stack.

# Detailed design
[design]: #detailed-design

This document describes how Kubewarden versioning works and how users can upgrade
their stack. The Kubewarden project uses [Semantic versioning](https://semver.org/)
to define the version of all its components. In other words, the version follows
the `MAJOR.MINOR.PATCH` pattern.  The supported version is only the latest release.

The Kubewarden components that follow the rules described here are:

- `kubewarden-controller`
- `policy-server`
- `kwctl`

`kubewarden-controller`, `policy-server` and `kwctl` share the same `MAJOR`
and `MINOR` version. The `PATCH` version can increase independently though.

## Version compatibility among components

`kubewarden-controller`, `policy-server` and `kwctl` should run the same `MAJOR`/`MINOR`.
Therefore, if the `kubewarden-controller` version running is `1.1.x`, the
`policy-server` and `kwctl` version in use should be `1.1.x` as well.

## Upgrade paths

When upgrading components, it is allowed to upgrade multiple `PATCH` version
in a single shoot. However, the upgrade of multiple `MAJOR` or `MINOR` versions
in a single upgrade is **not** supported.

For example, the user is allowed to upgrade components from version `1.1.10` to
`1.1.50` in a single upgrade. But the upgrade from `1.1.10` to `1.5.0` is not supported.
In these cases, the user must upgrade individually to each `MAJOR`/`MINOR` version
between the two versions. Therefore, it's necessary to upgrade `1.1.10` to `1.2.0`
then `1.3.0` then `1.4.0` and finally to `1.5.0`. Users that want to upgrade one
`MAJOR` version to another, also need to follow all the `MINOR` updates between the
two `MAJOR` versions.

## Upgrade order

Kuberwarden users should upgrade the stack starting in the `kubewarden-controller`.
After that, the `policy-server` and `kwctl` can be upgraded.

# Drawbacks
[drawbacks]: #drawbacks


# Alternatives
[alternatives]: #alternatives


# Unresolved questions
[unresolved]: #unresolved-questions
When upgrading major version, is it necessary upgrade minor version individually as well?

Do we really want to keep the two latest releases under active maintenance?
I think just keeping the latest version is enough for now.


# References

https://github.com/kubewarden/rfc/pull/2#issuecomment-1128965121
