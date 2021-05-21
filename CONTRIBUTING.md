# Contributing

## Commit titles

Commit titles matter when a release is tagged and the changelog is
generated.

The changelog will skip all commits that do not follow a specific
structure. The structure of the commit title is as follows:

- `type(scope): subject`

Scope is optional. Some commit title examples that would be included
in the changelog:

- `feat: this is a feature that involves several components`
- `feat(docs): allow users to report documentation errors`
- `perf(policy-server): cache policy results`
- `fix(controller): properly update ClusterAdmissionPolicy status subresource`
- `refactor(policy-server): move common code to external crates`

## Tagging a new release

### Create a new tag

#### Requirements

It is required to have the
[`git-chglog`](https://github.com/git-chglog/git-chglog) project
installed for automatic changelog generation to work. Install it like
so:

```console
$ go get -u github.com/git-chglog/git-chglog/cmd/git-chglog@v0.14.2
```

For creating a new release, first create a new tag:

```console
$ TAG=vX.Y.Z make tag
```

This will also update the `CHANGELOG.md` file on a separate
commit. Tag that commit as the release.

```console
$ git tag -m "Release X.Y.Z" -s vX.Y.Z
```

### Push new tag to the upstream repository

Assuming your official kubewarden remote is called `upstream`:

```console
$ git push upstream vX.Y.Z
```

Check that the Github actions are properly executed and have no
errors. With regards to the release, several automation tasks should
have been started:

1. Execute tests
1. Create a new Github release
1. Push a tagged container image with the build of the project

For a release to be complete, all these tasks should have been
executed succesfully.

### Consider bumping the helm-chart

Now that the controller has a new tag released, consider bumping the
[`helm-chart`](https://github.com/kubewarden/helm-charts/tree/main/charts/kubewarden-controller).
