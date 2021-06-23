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

## Completion

`kwctl` can generate autocompletion scripts for the following shells:

* bash
* elvish
* fish
* powershell
* zsh

The completion script can be generated with the following command:

```console
$ kwctl completions -s <SHELL>
```

The command will print to the stdout the completion script.

### Bash

To load completions in your current shell session:

```console
$ source <(kwctl completions -s bash)
```

To load completions for every new session, execute once:

* Linux: `$ kwctl completions -s bash > /etc/bash_completion.d/kwctl`
* MacOS: `$ kwctl completions -s bash > /usr/local/etc/bash_completion.d/kwctl`

You will need to start a new shell for this setup to take effect.

### Fish

To load completions in your current shell session:

```console
$ kwctl completions -s fish | source
```

To load completions for every new session, execute once:

```console
$ kwctl completions -s fish > ~/.config/fish/completions/kwctl.fish
```

You will need to start a new shell for this setup to take effect.

### Zsh

To load completions in your current shell session:

```console
$ source <(kwctl completions -s zsh)
```

To load completions for every new session, execute once:

```console
$ kwctl completions -s zsh > "${fpath[1]}/_kwctl"
```
