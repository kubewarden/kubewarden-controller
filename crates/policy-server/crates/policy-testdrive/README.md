chimera-policy-testdrive is a CLI tool for quickly testing chimera policies.

The tool takes the following data as input:

  * `--policy <POLICY.wasm>`: path to the WASM module that provides the policy to
    be evaluated. Currently only local files can be loaded.
  * `--request-file <REQUEST.json>`: path to the json file with the Kubernetes
    admission requet object to be evaluated.
  * `--settings <JSON DICTIONARY>`: json dictionary with the settings used by
    the policy at evaluation time.

`policy-testdrive` evaluates the request and prints the validation response to
the standard output.

## Example

We want to test this [pod toleration policy](https://github.com/chimera-kube/pod-toleration-policy)
against a pre-recorded Kubernetes admission request. The admission request is
saved inside of a file called `test_request.json`.

We want to run the policy with the following settings. Note well, this would
be the syntax used inside of [policy-server](https://github.com/chimera-kube/policy-server)'s
`policies.yml` file:

```yaml
settings:
  - taint_key: dedicated
  - taint_value: tenantA
  - allowed_groups: tenantA-users
```

This command will evaluate the policy against a pre-recorded Kubernetes admission
request object:

```shell
$ chimera-policy-testdrive \
    --policy pod-toleration-policy.wasm \
    --request-file test_request.json \
    --settings '{"taint_key": "dedicated", "taint_value": "tenantA", "allowed_groups": "tenantA-users"}'
```
