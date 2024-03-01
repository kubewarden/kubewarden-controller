# Contributing

## Building

To build kubewarden-controller some packages are required. If you are using
openSUSE Leap, you can install them with the following command:

```
sudo zypper in -y make go
```

Then, can run the following command to build the package:

```
make
```

## Development

To run the controller for development purposes, you can use [Tilt](https://tilt.dev/).

### Pre-requisites

Please follow the [Tilt installation documentation](https://docs.tilt.dev/install.html) to install the command line tool.
You need to clone the [kubewarden helm-charts repository](https://github.com/kubewarden/helm-charts) in your local machine:

```console
$ git clone git@github.com/kubewarden/helm-charts.git
```

A development Kubernetes cluster is needed to run the controller.
You can use [k3d](https://k3d.io/) to create a local cluster for development purposes.

### Settings

The `tilt-settings.yaml.example` acts as a template for the `tilt-settings.yaml` file that you need to create in the root of this repository.
Copy the example file and edit it to match your environment.
The `tilt-settings.yaml` file is ignored by git, so you can safely edit it without worrying about committing it by mistake.

The following settings can be configured:

- `registry`: the container registry where the controller image will be pushed. If you don't have a private registry, you can use `ghcr.io` as long as your cluster has access to it.
- `image`: the name of the controller image. If you are using `ghcr.io` as your registry, you need to prefix the image name with your GitHub username.
- `helm_charts_path`: the path to the `helm-charts` repository that you cloned in the previous step.

Example:

```yaml
registry: ghcr.io
image: your-github-username/kubewarden-controller
helmChartPath: /path/to/helm-charts
```

### Running the controller

The `Tiltfile` included in this repository will take care of the following:

- Install the CRDs from the `config/crd/` directory of this repository.
- Install `cert-manager`.
- Create the `kubewarden` namespace and install the controller helm-chart in it.
- Inject the development image in the deployment.
- Automatically reload the controller when you make changes to the code.

To run the controller, you just need to run the following command against an empty cluster:

```console
$ tilt up --stream
```

## Tagging a new release

### Make sure CRD docs are updated:

```console
$ cd docs/crds
$ make generate
$ # commit resulting changes
```

### Create a new tag

Assuming your official kubewarden remote is called `upstream`:

```console
$ git tag -a vX.Y.Z  -m "vX.Y.Z" -s
$ git push upstream main vX.Y.Z
```

Check that the Github actions are properly executed and have no
errors. With regards to the release, several automation tasks should
have been started:

1. Execute tests
1. Create a new Github release
1. Push a tagged container image with the build of the project

For a release to be complete, all these tasks should have been
executed successfully.

### Consider bumping the helm-chart

Now that the controller has a new tag released, the automation will bump the
[`helm-chart`](https://github.com/kubewarden/helm-charts/tree/main/charts/kubewarden-controller).

### Consider announcing the new release in channels!

## Kubewarden release template

If you are releasing the Kubewarden stack there are some steps that we can follow to ensure that everything goes fine:

- [ ] Update controller code
- [ ] Run controller tests or check if the CI is green in the main branch
- [ ] Update audit scanner code
- [ ] Run audit scanner tests or check if the CI is green in the main branch
- [ ] Bump policy server version in the `Cargo.toml` and update the `Cargo.lock` file.  This will require an PR in the repository to update the files in the main branch. Update the local code after merging the PR
- [ ] Run policy server tests or check if the CI is green in the main branch
- [ ] Bump kwctl version in the `Cargo.toml` and update the `Cargo.lock` file.  This will require an PR in the repository to update the files in the main branch. Update the local code after merging the PR
- [ ] Run kwctl tests  or check if the CI is green in the main branch
- [ ] Tag audit scanner
- [ ] Tag policy server
- [ ] Tag controller
- [ ] Tag kwctl
- [ ] Wait for all CI running in all the major components (audit scanner, controller, policy server and kwctl) to finish
- [ ] Check if the Helm chart repository CI open a PR updating the Helm charts with the correct changes.
- [ ] Check if CI in the Helm chart PR is green. If so, merge it
