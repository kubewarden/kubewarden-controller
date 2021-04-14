# Contributing

## Tagging a new release

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
the controller
[`helm-chart`](https://github.com/kubewarden/helm-charts/tree/main/charts/kubewarden-controller),
so by default it will deploy the latest version of the policy server.
