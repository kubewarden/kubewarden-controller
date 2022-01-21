|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Policy Signing                   |
| Start Date   | 21 Jan 2022                      |
| Category     | Security                         |
| RFC PR       | [#147](https://github.com/kubewarden/kubewarden-controller/pull/147)  |

# Summary
[summary]: #summary

We want to provide a way to verify the integrity and authenticity of our policies, so that end-users can trust them.

To accomplish that, we will provide ways to sign and verify policies.

The main driver for this change is to be able to comply with [`SLSA`](https://slsa.dev/)
directives about Secure Software Supply Chain.

# Motivation
[motivation]: #motivation

Our policies are binary blobs, that makes hard to ensure the policy we're about to run
matches with the source code tagged inside of a git repository.

This is what we want to achieve with this proposal:

* policy authors: have a way to sign their policies, to attest their provenance.
* end users: have a way to verify the integrity of a policy that they want to load inside of their cluster. Allow them to execute only policies they trust.

## Examples / User Stories
[examples]: #examples

### Execute only policies coming from trusted parties

> As a Kubernates administrator,
> I want to enforce only Kubewarden policies that have been produced by authors I trust to be loaded.

### Execute only policies that have been approved by selected people

> As a group of Kubernetes administrators,
> we want to deploy in production only policies that we have approved.

In that case, the Kubernetes administrators would:

  * Download a pre-built Kubewarden policy
  * Verify it's being signed by its author
  * Push it to a (possibly internal) registry
  * All the Kubernetes administrators would sign the policy
  * The policy is loaded only if all the Kubernetes administrators signed the policy


# Detailed design
[design]: #detailed-design

We're going to use [Sigstore](https://sigstore.dev) to sign and verify our policies.

Sigstore allows policies to be signed either with a pub/private keypair or with
[KEYLESS](https://github.com/sigstore/cosign/blob/main/KEYLESS.md)
signing.

## How Sigstore signatures work

This is a quick overview of the different kind of signatures that could be produced by Sigstore.

Even though we will use just one method to sign our policies, we will have to support
all of them in order to allow the use cases described above. We don't know how users and 3rd party
developers will sign their policies.

It's important to know that a policy can be signed in multiple ways. Multiple people can sign the
policy. The same user can sign it multiple times, using different methods.

### Public/private key pair

This is the simplest way of signing. The policy author uses his private key to sign
the policy.

The end user needs the public key of the author to verify the policy.

### Keyless signing outside of GitHub Action

The policy author signs the policy in keyless mode. This is the workflow:

  * The author executes `cosign sign ...`
  * Cosign prints a URL on the standard output
  * Author clicks on the link, he's redirected to a dedicated landing page of Sigstore
  * Author picks an identity provider from the list shown on the page (GitHub, Outlook, Google,...)
  * Author is redirected to the identity provider, enters his credentials and allows the identity provider to share some details with Sigstore.
    This is the same process that happens when, for example, you sign into a website using your Gmail identity
  * The identity provider returns a OIDC token
  * The information inside of the OIDC token is used to generate some details of the final signature

As an end result, the signature will look like that:

```hcl
{
  "critical": {
    // not relevant
  },
  "optional": {
    "Bundle": {
    // not relevant
    },
    "Issuer": "https://github.com/login/oauth",
    "Subject": "user@provider.com"
  }
}
```

The end user needs to know the email address used by the policy author.

### Keyless signing inside of GitHub Action

Each GitHub Action runs inside of an environment where a OIDC token is provided
by GitHub.

Sigstore's cosign can leverage this already existing OIDC token to sign artifacts. This
signature process happens in non-interactive mode, which is great for CD pipelines.

This is how the signature looks like:

```hcl
{
  "critical": {
    // not relevant
  },
  "optional": {
    "Bundle": {
    // not relevant
    },
    "Issuer": "https://token.actions.githubusercontent.com",
    "Subject": "https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"
  }
}
```

The relevant information are the `Issuer` and `Subject` fields.

All the objects signed via GitHub Actions in non-interactive mode have the `Issuer` field set to
`https://token.actions.githubusercontent.com`.

The `Subject`, on the other hand, is built using:

  * The repository that contains the source code of the policy
  * The full path to the Yaml file where the `cosign sign` invocation is written
  * The branch: `main` or a `tag`

This somehow unique `Subject` is nice, because it's more granular.
However, that makes the end user experience uglier.

In the previous cases, the identity of the policy author never changed: it was
either his public key or his email address.

In this case, the `Subject` keeps changing:

  * It's different on a per policy basis: each policy lives inside of a different
    repository
  * It's different even for the very same policy:
    * It changes based on the release: that's because the git tag is part of the URL
    * Even keeping the same tag (like `main` - which would be horrible from a security
      POV), the URL could change if the Yaml file that invokes `cosign sign` is renamed.

## Signing Kubewarden policies

We want to sign our policies inside of the GitHub Action that takes care of pushing
them to our container registry.
We want to sign them in keyless mode, using the GitHub Action OIDC token.

Given that our builds take place inside of GitHub Actions, the usage
of keyless signing offers us the most secure setup we can achieve inside of this
context.

This leads us to find a solution that solves the problem of the "mutating `Subject`".
We want end users have a good experience but, at the same time, we don't want to weaken
the strengths of our signatures.

Given a `Subject`:

```json
{
  "Subject": "https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"
}
```

We can easily understand who is the owner of the repository that built the policy.
That could be an individual user or an organization.

We plan to allow end users to define an "allow list" of GitHub users/organizations
that can be trusted.

## Verifying policies

Policy verification settings are going to be defined using a dedicated configuration
file. This file format is going to be shared between Policy Server and kwctl.

The proposed format is the following one:

```yaml
apiVersion: v1

allOf:
  - kind: githubAction
    owner: kubewarden   # mandatory
    annotations:
      env: prod

anyOf: # at least `anyOf.minimumMatches` are required to match
  minimumMatches: 2 # default is 1
  signatures:
  - kind: pubKey
    owner: flavio # optional
    key: .... # mandatory
    annotations:  # optional
      env: prod
      foo: bar
  - kind: pubKey
    owner: victor # optional
    key: .... # mandatory
  - kind: genericIssuer
    isser: https://github.com/login/oauth
    subjectEqual: alice@example.com
  - kind: genericIssuer
    issuer: https://token.actions.githubusercontent.com
    subjectEqual: https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main
  - kind: genericIssuer
    issuer: https://token.actions.githubusercontent.com
    subjectUrlPrefix: https://github.com/flavio/
  - kind: genericIssuer
    issuer: https://token.actions.githubusercontent.com
    subjectUrlPrefix: https://github.com/kubewarden # <- it will be post-fixed with `/` for security reasons
  - kind: githubAction
    owner: flavio   # mandatory
    repo: policy1 # optional
  - kind: pubKey
    owner: alice # optional
    key: .... # mandatory
```

The file is composed by two sections:

  * `allOf`: all the `SignatureRequirement`s specified inside of this section are mandatory.
    Each policy must be signed by all of the mentioned Signers
  * `anyOf`: this is a list of `SignatureRequirement`s that are searched inside of the policy
    signatures. The `minimumMatches` value (which has a default value of `1`)
    defines the minimum number of verified signatures that each policy must have. This behavior can be used as a feature when migrating between signatures.


### Types of signatures

There are different types of `SignatureRequirement` objects, we're goint to describe
them in the next sections..

Before doing that, it's important to point out that each `SignatureRequirement`
object has an optional attribute called `annotations`. This is a
key/value map with a list of cosign annotations that must be found inside of
the cosign Signature.

For example, given the following `SignatureRequirement`:

```yaml
- kind: pubKey
  owner: flavio # optional
  key: .... # mandatory
  annotations:
    env: prod
    foo: bar
```

This requirement is satisfied only when all these conditions are true:

  * The signature is verified using the public key provided inside of the `key`
    attribute
  * The signature must have all the annotations specified: `env` with value `prod` and
    `foo` with key `bar`. It doesn't matter if the signature has even more annotations.

#### SignatureRequirement `pubKey`

This `SignatureRequirement` targets signatures produced via a private key:

```yaml
  - kind: pubKey
    owner: flavio # optional
    key: |
      -----BEGIN PUBLIC KEY-----
      MBFKHFDGHKIJH0CAQYIKoZIzj0DAQcDQgAEX0HFTtCfTtPmkx5p1RbDE6HJSGAVD
      BVDF6SKFSF87AASUspkQsN3FO4iyWodCy5j3o0CdIJD/KJHDJFHDFIu6sA==
      -----END PUBLIC KEY-----
```

The `owner` attribute is optional, while the `key` one is mandatory.

#### SignatureRequirement `genericIssuer`

This is used to target signatures produced in keyless mode.

The `issuer` attribute is mandatory, and is used to match the `Issuer`
attribute inside of the certificate issued by Fulcio's PKI.

The `SignatureRequirement` then performs a comparison operation
abainst the `Subject` attribute of the certificate issued by Fulcio's PKI.
These are the constrains we plan to offer since the first release:

  * `subjectEqual`: the `Subject` inside of the signature must be
    equal to the one specified inside of the `SignatureRequirement`
  * `subjectUrlPrefix`: the value provided inside of the `SignatureRequirement`
    is terminated with a `/` char for security reasons, unless it already ends with that. Then this
    value must match with the prefix of the signature's `Subject`.

Let's make some examples.

Performing a strict check of the `Subject`:

```yaml
- kind: genericIssuer
  isser: https://github.com/login/oauth
  subjectEqual: alice@example.com

```

The following signature is going to satisfy the `SignatureRequirement`
shown above:

```hcl
{
  "critical": {
    // not relevant
  },
  "optional": {
    "Bundle": {
    // not relevant
    },
    "Issuer": "https://github.com/login/oauth",
    "Subject": "alice@example.com"
  }
}
```

Performing a URL check:

```yaml
- kind: genericIssuer
  issuer: https://token.actions.githubusercontent.com
  subjectUrlPrefix: https://github.com/flavio
```

The string inside of `subjectUrlPrefix` is automatically suffixed with the `/`
char, because of that it becomes: `https://github.com/flavio/`.

The following signature is going to satisfy the `SignatureRequirement`
shown above:

```hcl
{
  "critical": {
    // not relevant
  },
  "optional": {
    "Bundle": {
    // not relevant
    },
    "Issuer": "https://token.actions.githubusercontent.com"
    "Subject": "https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"
  }
}
```

On the other hand, this signature is **not** going to be trusted:

```hcl
{
  "critical": {
    // not relevant
  },
  "optional": {
    "Bundle": {
    // not relevant
    },
    "Issuer": "https://token.actions.githubusercontent.com"
    "Subject": "https://github.com/flavio-hacker/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"
  }
}
```

#### SignatureRequirement `githubAction`

A lot of users are relying on GitHub Actions to implement their CD pipelines.
We expect many policies to be signed using the seamless integration that GitHub
Actions offer.

While these signatures can be verified with the `genericIssuer` and the `subjectUrlPrefix`
constrain, we want to offer a better user experience.

Because of that, we provide the `SignatureRequirement` with type `githubAction`:

```yaml
- kind: githubAction
  owner: flavio                  # mandatory
  repo: policy-secure-pod-images # optional
```

This defines the following attributes:

  * `owner` (required): the ID of the GitHub user or Organization to be trusted
  * `repo` (optional): the name of the repository to be trusted

The following signature will be verified:

```hcl
{
  "critical": {
    // not relevant
  },
  "optional": {
    "Bundle": {
    // not relevant
    },
    "Issuer": "https://token.actions.githubusercontent.com"
    "Subject": "https://github.com/flavio/policy-secure-pod-images/.github/workflows/release.yml@refs/heads/main"
  }
}
```

Given the following `SignatureRequirement`:

```yaml
- kind: githubAction
  owner: kubewarden
```

All the policies signed by the Kubewarden organization via GitHub Actions are
going to be trusted.

## Configuration scenarios

### Only `allOf` is specified

```yaml
apiVersion: v1

allOf:
  - kind: githubAction
    owner: kubewarden
    annotations:
      env: prod
  - kind: pubKey
    owner: flavio
    key: ....
```

With this configuration, all the policies must:

  * Be signed by a GitHub Action, with the build happening inside of the `kubewarden`
    organization. Moreover, these signatures must have an annotation with the key
    `env` set to `prod`.
  * Be signed with the public key of the user flavio

### Only `anyOf` is specified

```yaml
apiVersion: v1

anyOf:
  minimumMatches: 2
  - kind: githubAction
    owner: kubewarden
    annotations:
      env: prod
  - kind: pubKey
    owner: flavio
    key: ....
  - kind: genericIssuer
    isser: https://github.com/login/oauth
    subjectEqual: alice@example.com
```

With this configuration, all the policies must be satisfy 2 or more `SignatureRequirement`.

For example:
  * policy #1 could be signed by the public key of flavio and by Alice, only if she authenticated
    herself using her GitHub account
  * policy #2 could be signed by the public key of flavio and by a GitHub Action that
    was expected inside of the `kubewarden` organization. The signature produced by
    the GitHub Action must also provide an annotation with key `env` and value `prod`.
  * policy #3 could be signed by the GitHub Action, flavio's private key and by
    Alice

When not specified, `minimumMatches` has value `1`.

### Both `allOf` and `anyOf` are specified

```yaml
apiVersion: v1

allOf:
  - kind: githubAction
    owner: kubewarden
    annotations:
      env: prod
anyOf:
  minimumMatches: 2
  - kind: pubKey
    owner: bob
    key: ....
  - kind: pubKey
    owner: flavio
    key: ....
  - kind: genericIssuer
    isser: https://github.com/login/oauth
    subjectEqual: alice@example.com
```

All the policies must be signed by a GitHub Action that was executed inside of the
`kubewarden` organization, plus the signature must have an annotation with key
`env` and value `prod`.

In addition to that (**AND** logical operator), each policy signature must also
satisfy 2 or more of the `SignatureRequirement` specified inside of the `anyOf`.

It's "2 or more", because this is the threshold set by the `minimumMatches` attribute.

### Neither `allOf` nor `anyOf` are specified

This is an invalid configuration, no verification would be possible.

This will raise an error.


# Drawbacks
[drawbacks]: #drawbacks

Policy signature verification is going to be an opt-in feature.

There's no reason to not implement this feature.

# Alternatives
[alternatives]: #alternatives

## Specify per-policy signature settings

We could ask operators to put the signature verification settings
inside of the `ClusterAdmissionPolicy` definition.

For example:

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: privileged-pods
  annotations:
    subject.cosign.sigstore.dev: https://github.com/kubewarden/privileged-pods/.github/workflows/release.yml@refs/tags/v0.1.9
    issuer.cosign.sigstore.dev: https://token.actions.githubusercontent.com
spec:
  module: registry://ghcr.io/kubewarden/policies/pod-privileged:v0.1.9
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    operations:
    - CREATE
    - UPDATE
  mutating: false
```

The same could be done to embed the public key to be used.

We do not feel comfortable with this behaviour:

  * The security settings can be provided by whoever has the RBAC rights to create/modify `ClusterAdmissionPolicy`
    objects.
  * The UX is still ugly for policies that signed inside of GitHub Actions using the non-interactive mode
  * This approach can be applied only by Policy Server, kwctl would have to verify policies in a different way because it
    doesn't rely on `ClusterAdmissionPolicy` objects to run/pull policies.

## Embed the verification criteria inside of policy's metadata

Each Kubewarden policy has some user-defined metadata.

The process to publish a policy consists of the following steps:

  1. Edit the `metadata.yml` file
  2. Annotate the policy with the `metadata.yml` file. This produces a new `.wasm` file, which includes the metadata
  3. Push the policy to a registry
  4. Sign the policy using the immutable reference obtained inside of the previous step

We could add a new entry inside of policy's metadata, something like:

```yaml
subject.cosign.sigstore.dev: https://github.com/kubewarden/privileged-pods/.github/workflows/release.yml@refs/tags/v0.1.9
issuer.cosign.sigstore.dev: https://token.actions.githubusercontent.com
```

At verification time, we could look for a signature that satisfies the constrains provided inside of the policy metadata.

Alterning the policy's metadata would lead to a different `.wasm` file, which would
break the initial checks of sigstore's signature.

We've discarded this approach because, among other things, we think it's safer to provide the verification constraints
in an out-of-band way.

Moreover, this would make having reproducible builds more difficult.

# Unresolved questions
[unresolved]: #unresolved-questions

Doing keyless signing in a non-interactive way inside of other environments (GitLab, Tekton,...) could lead to a
`Subject` that is formatted in a completely different way compared to GitHub Action.

In that scenario our simple matching algorithm would not work.

The solution could be to create per-issuer ad-hoc configurations (with their custom verification logic).
