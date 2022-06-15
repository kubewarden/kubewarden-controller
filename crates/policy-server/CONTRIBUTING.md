# Contributing

## Commit subjects

Commit subjects are used to determine whether a commit will show up in
the `CHANGELOG.md`, and under what section.

Commit subjects that don't follow the following pattern will not be
included in the `CHANGELOG.md`:

- `type: free form subject`

Where `type` can be:

* `feat`: used by commits introducing a new feature
* `fix`: used by commits fix an issue
* `perf`: used by commits improving performance
* `refactor`: used by commits doing some code refactoring

Some examples:

- `feat: this is a new feature`
- `fix: this is fixing a reported bug`

It's also possible to specify a component if this commit targets one
component specifically.

- `feat(resolver): this adds a new solver strategy`

## Tagging a new release

### Bump Cargo.toml version

As usual, first bump the version in `Cargo.toml`.

### Create a new tag

For creating a new release, first create a new tag:

```console
$ TAG=vX.Y.Z make tag
```

This will also update the `CHANGELOG.md` file on a separate commit,
and tag that commit as the release.

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

Now that the policy-server has a new tag released, consider bumping
the version in the kubewarden-defaults
[`helm-chart`](https://github.com/kubewarden/helm-charts/tree/main/charts/kubewarden-defaults).
