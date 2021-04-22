# `kwctl`

`kwctl` is the go-to CLI tool for [Kubewarden](https://kubewarden.io)
users.

Think of it as the `docker` CLI tool if you were working with
containers.

## How does `kwctl` help me?

### As a policy author

- e2e testing of your policy. Test your policy against crafted
  Kubernetes requests, and ensure your policy behaves as you
  expect. You can even test context-aware policies, that require
  access to a running cluster.

- Embed metadata in your Wasm module, so the binary is annotated with
  the permissions it needs to execute.

- Publish policies to OCI registries.

- Generate initial `ClusterAdmissionPolicy` scaffolding for your
  policy.

### As a cluster administrator

- Inspect remote policies. Given a policy in an OCI registry, or in an
  HTTP server, show all static information about the policy.

- Dry-run of a policy in your cluster. Test the policy against crafted
  Kubernetes requests, and ensure the policy behaves as you expect
  given the input data you provide. You can even test context-aware
  policies, that require access to a running cluster, also in a
  dry-run mode.

- Generate `ClusterAdmissionPolicy` scaffolding for a given policy.

### Everyone

- The UX of this tool is intended to be as easy and intuitive as
  possible.
