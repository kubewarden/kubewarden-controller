[![Kubewarden Core Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-core.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#core-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9180/badge)](https://www.bestpractices.dev/projects/9180)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fkwctl.svg?type=shield)](https://app.fossa.com/projects/cjustom%2B25850%2Fgithub.com%2Fkubewarden%2Fkwctl?ref=badge_shield)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kubewarden/kwctl/badge)](https://scorecard.dev/viewer/?uri=github.com/kubewarden/kwctl)

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

## Install

Built binaries for `Linux x86_64`, `Windows x86_64`, `MacOS x86_64` and `MacOS
aarch64 (M1)` are available in [GH Releases](https://github.com/kubewarden/kwctl/releases).

There is also:

- Community-created [Homebrew 🍺 formula for kwctl](https://formulae.brew.sh/formula/kwctl)
- Community-created [AUR 🐧 package](https://aur.archlinux.org/packages/kwctl-bin)

## Usage

These are the commands currently supported by kwctl.

If you want a complete list of the available commands, you can read the 
[cli-docs.md](./cli-docs.md) file.

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

- `http://`: pull from a HTTP server
- `https://`: pull from a HTTPS server
- `registry://`: pull from an OCI registry

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

#### Scaffold AdmissionReview from a Kubernetes resource

It's possible to scaffold an `AdmissionReview` object from a Kubernetes resource:

```console
kwctl scaffold \
  admission-request \
  --operation CREATE \
  --object ingress.yaml
```

The output of the above command can be used by the `run` command.

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
apiVersion: policies.kubewarden.io/v1
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

- bash
- elvish
- fish
- powershell
- zsh

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

- Linux: `$ kwctl completions -s bash > /etc/bash_completion.d/kwctl`
- MacOS: `$ kwctl completions -s bash > /usr/local/etc/bash_completion.d/kwctl`

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

kwctl binaries are signed using [Sigstore's blog signing](https://docs.sigstore.dev/signing/signing_with_blobs/).
When you download a [kwctl release](https://github.com/kubewarden/kwctl/releases/) each zip file contains two
files that can be used for verification: `kwctl.sig` and `kwctl.pem`.

In order to verify kwctl you need cosign installed, and then execute the following command:

```
cosign verify-blob \
  --signature kwctl-linux-x86_64.sig \
  --cert kwctl-linux-x86_64.pem kwctl-linux-x86_64 \
  --certificate-identity-regexp 'https://github.com/kubewarden/*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The output should be:

```
Verified OK
```

# Software bill of materials & provenance

Kwctl has its software bill of materials (SBOM) published every release. They
follow the [SPDX](https://spdx.dev/) format, you can find them together with
the signature and certificate used to sign it in the [releases
assets](https://github.com/kubewarden/kwctl/releases).

The build [Provenance](https://slsa.dev/spec/v1.0/provenance) files are
following the [SLSA](https://slsa.dev/provenance/v0.2#schema) provenance schema
and are accesible at the GitHub Actions'
[provenance](https://github.com/kubewarden/kwctl/attestations) tab. For
information on their format and how to verify them, see the [GitHub
documentation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline).

## Security disclosure

See [SECURITY.md](https://github.com/kubewarden/community/blob/main/SECURITY.md) on the kubewarden/community repo.

## Changelog

See [GitHub Releases content](https://github.com/kubewarden/kwctl/releases).
