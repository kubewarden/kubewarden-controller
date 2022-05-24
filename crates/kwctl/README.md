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

## Usage

These are the commands currently supported by kwctl.

### List policies

The list of policies downloaded on the local machine can be
obtained by doing:

```console
kwctl policies
```

### Download policies

Policies can be downloaded using the `pull` command.

The name of the policy must be expressed as a url with one of the
following protocols:

* `http://`: pull from a HTTP server
* `https://`: pull from a HTTPS server
* `registry://`: pull from an OCI registry

Pulling from a registry, by tag:

```console
kwctl pull registry://ghcr.io/kubewarden/policies/psp-capabilities:latest
```

It's possible to pull from a registry using an immutable reference (in the
same way as with regular container images):

```console
kwctl pull registry://ghcr.io/kubewarden/policies/psp-capabilities@sha256:61ef63621fa5be8e422881d96d05edfef810992fbf9468e35d1fa5ae815bd97c
```
Note well, the shasum is the digest of the OCI artifact containig the policy.
This value can be obtained using a tool like [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md):

```console
crane digest ghcr.io/kubewarden/policies/psp-capabilities:v0.1.6
```

### Run a policy locally

`kwctl` can be used to run a policy locally, outside of Kubernetes. This can be used 
to quickly evaluate a policy and find the right settings for it.

The evalution is done against a pre-recorded [`AdmissionReview`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request).


Running a policy locally:

```console
kwctl run \
  --settings-json '{"constrained_labels": {"owner": ".*"}}' \
  -r test_data/ingress.json \
  registry://ghcr.io/kubewarden/policies/safe-labels:v0.1.5
```

Policy configuration can be passed on the CLI via the `--settings-json` flag
or can be loaded from the disk via the `--settings-path` flag.

### Annotate a policy

Kubewarden policies are WebAssembly module, which must contain some
Kubewarden-spefic metadata.

The act of adding metadata to the policy is done by the policy author, right
before policy distribution.

The `kwctl annotate` command can be used to perform this operation.

### Inspect a policy

The metadata attached to a policy, plus other details can be seen via the
`kwctl inspect` command.

This command works against a policy that has been previously downloaded.

### Publish a policy

`kwctl` can be used to publish a local policy into an OCI registry. This is done
via the `push` sub-command.

The `push` sub-command can also be used to copy a policy into another registry:

```console
kwctl push registry://ghcr.io/kubewarden/policies/safe-labels:v0.1.5 \
  registry://registry.local.lan/kubewarden/safe-labels:v0.1.5
```

The above command copies a local policy that was downloaded from the GitHub
Container Registry, into a local registry.

> **Note well:** the policy must be previously downloaded locally via `kwctl pull`

### Remove a local policy

Local policies can be removed via the `rm` sub-command:

```console
kwctl rm <name of the policy>
```

### Scaffold Kubernetes Custom Resources

Kubewarden policies are enforced on Kubernetes clusters by using
special Custom Resources provided by our [Kubernetes integration](https://docs.kubewarden.io/quick-start.html#kubewarden-policies).

The `manifest` sub-command can be used to quickly scaffold the definition of
Kubewarden Custom Resources.

The manifest command shares some of the arguments of the `run` command, it's
typical to test a policy locally via the `kwctl run` command and then, once
satisfied about the policy settings, create a deployment manifest for it via
the `manifest` command.

Step #1, find the right policy settings:

```console
kwctl run \
  --settings-json '{"constrained_labels": {"owner": ".*"}}' \
  -r test_data/ingress.json \
  registry://ghcr.io/kubewarden/policies/safe-labels:v0.1.5
```

Step #2, generate a manifest to enforce the policy inside of a
Kubernetes cluster:


```console
kwctl manifest\
  --settings-json '{"constrained_labels": {"owner": ".*"}}' \
  -t ClusterAdmissionPolicy \
  registry://ghcr.io/kubewarden/policies/safe-labels:v0.1.5
```

This will produce the following output:

```yaml
---
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: generated-policy
spec:
  module: "registry://ghcr.io/kubewarden/policies/safe-labels:v0.1.5"
  settings:
    constrained_labels:
      owner: ".*"
  rules:
    - apiGroups:
        - "*"
      apiVersions:
        - "*"
      resources:
        - "*"
      operations:
        - CREATE
        - UPDATE
  mutating: false
```

Which can then be customized by hand, and then applied into a Kubernetes cluster.

### Shell completion

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

#### Bash

To load completions in your current shell session:

```console
$ source <(kwctl completions -s bash)
```

To load completions for every new session, execute once:

* Linux: `$ kwctl completions -s bash > /etc/bash_completion.d/kwctl`
* MacOS: `$ kwctl completions -s bash > /usr/local/etc/bash_completion.d/kwctl`

You will need to start a new shell for this setup to take effect.

#### Fish

To load completions in your current shell session:

```console
$ kwctl completions -s fish | source
```

To load completions for every new session, execute once:

```console
$ kwctl completions -s fish > ~/.config/fish/completions/kwctl.fish
```

You will need to start a new shell for this setup to take effect.

#### Zsh

To load completions in your current shell session:

```console
$ source <(kwctl completions -s zsh)
```

To load completions for every new session, execute once:

```console
$ kwctl completions -s zsh > "${fpath[1]}/_kwctl"
```

##### Oh My Zsh users

These steps are required by [oh-my-zsh](https://ohmyz.sh/) users:

```console
$ print -l $fpath | grep '.oh-my-zsh/completions'
$ mkdir ~/.oh-my-zsh/completions
$ kwctl completions -s zsh > ~/.oh-my-zsh/completions/_kwctl
rm ~/.zcompdump*
```

Then start a new shell or run `source ~/.zshrc` once.

## Verify kwctl binaries

kwctl binaries are signed using [Sigstore](https://docs.sigstore.dev/cosign/working_with_blobs/#signing-blobs-as-files). 
Each release contains two files: kwctl.sig and kwctl.pem that can be used for verification.

In order to verify kwctl you need cosign installed, and then execute the following command:

```
COSIGN_EXPERIMENTAL=1 cosign verify-blob  --signature kwctl-linux-x86_64.sig --cert kwctl-linux-x86_64.pem kwctl-linux-x86_64
```

The output should be:

```
tlog entry verified with uuid: 7e5a4fac8f45cdddeafd6901af566b9576be307a06caa3fbc45f91da102214e0 index: 2435066
Verified OK
```