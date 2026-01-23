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
