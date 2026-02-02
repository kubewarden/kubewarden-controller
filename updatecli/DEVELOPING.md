# Release automation

You can trigger the pipeline and open the PR from your local machine
as needed.

Change `updatecli/values.yaml` as needed to target forks.

```console
$ cd kubewarden-controller/
$ export UPDATECLI_GITHUB_TOKEN=<your token>
$ clear; updatecli apply --config updatecli/updatecli.release.d/open-release-pr.yaml \
  --values updatecli/values.yaml \
  --debug --clean=true

(...)

Run Summary
===========
Pipeline(s) run:
  * Changed:    1
  * Failed:     0
  * Skipped:    0
  * Succeeded:  0
  * Total:      1

One action to follow up:
  * https://github.com/viccuad/kubewarden-controller/pull/1
```

## Dependency Updates

All dependency updates are consolidated into a single weekly workflow.

### Weekly Dependency Updates
Runs weekly (Monday 3:30 AM) via `.github/workflows/update-dependencies.yaml` using `update-deps.yaml`.

Updates the following dependencies:
- Go version in `go.mod` and Dockerfiles
- Policy image tags in Helm chart values
- Policy-reporter chart version
- Kuberlr-kubectl image version
- Hauler manifest with all component versions

### Running Updates Manually
For manual runs of all dependency updates:
```console
$ export UPDATECLI_GITHUB_TOKEN=<your token>
$ export UPDATECLI_GITHUB_OWNER=kubewarden
$ updatecli compose diff --file updatecli/update-deps.yaml
```
