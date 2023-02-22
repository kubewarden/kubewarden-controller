|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Unified metadata                 |
| Start Date   | Jan 18 2023                      |
| Category     | [Category]                       |
| RFC PR       | https://github.com/kubewarden/rfc/pull/15  |
| State        | **ACCEPTED**                         |


# Summary
[summary]: #summary

Policies have metadata information that must be made accessible to different
consumers (policy-evalutor, artifacthub). Each consumer ingests the metadata
in slightly different formats. We want to provide a way to reduce the manual
operations required to keep the different metadata files up to date.

# Motivation
[motivation]: #motivation

Currently each Kubewarden policy has a `metadata.yml` file that defines some
metadata information about the policy. This information is used by policy-evaluator
(hence by kwctl and policy-server) when executing a policy. It's mandatory for
policies to be "annotated" with this metadata in order to be used.

Policies published on [Artifact Hub](https://artifacthub.io) have an additional
metadata file, called `artifacthub-pkg.yml`.

There's some duplication of data between the two files, keeping these two files 
in sync is error prone and time expensive. There's the risk of having "metadata drift"
between the two files.

This proposal aims to provide a solution to this problem.

## Examples / User Stories
[examples]: #examples

## Publishing a policy on Artifact Hub for the first time

As a policy author, I want to publish my policy on Artifact Hub. My policy has
already a `metadata.yml` file, however I have to copy-paste, adapt and expand
the contents of `metadata.yml` into the `artifacthub-pkg.yml` file.

I would rather have a way to automatically generate the `artifacthub-pkg.yml` file.

## Tag a new release of a policy

As a policy author, I'm about to publish a new version of my policy. This policy
is also registered on Artifact Hub.

I would like to have some automation that updates the contents of the already
existing `artifacthub-pkg.yml` file.

# Detailed design
[design]: #detailed-design

Each Kubewarden policy must have a `metadata.yml` file. While only certain ones
are going to have a `artifacthub-pkg.yml` file.

We want to have the following workflow:

* User creates a `metadata.yml` file. This file is scaffolded when the policy
  is created for the 1st time
* User enters proper data inside of `metadata.yml`
* User keeps annotating the policy in the usual way: `kwctl annotate --metadata-path `metadata.yml`

If the user wants to publish the policy on Artifact Hub, we will offer the following
workflow:

* User extends the `metadata.yml` file with some annotations that are specific
  to Artifact Hub
* User invokes: `kwctl scaffold artifacthub --metadata-path metadata.yml`.
  This command will generate the `artifacthub-pkg.yml` file

The freshly created `kwctl scaffold artifacthub` can be run as many times
as the user wants. The contents of `artifacthub-pkg.yml` are going to be
overwritten.

It's important to point out that a user can completely avoid this workflow and
keep managing the `artifacthub-pkg.yml` file as he prefers.

## Comparing `metadata.yml` and `artifacthub-pkg.yml`

The following snippet is taken from one of our policies, it
includes all the mandatory fields:

```yaml
---
# metadata.yml
rules:
- apiGroups: [""]
  apiVersions: ["v1"]
  resources: ["pods"]
  operations: ["CREATE", "UPDATE"]
mutating: true
contextAware: false
executionMode: kubewarden-wapc
annotations: {}
```

The `annotations` key holds a dictionary where both keys and values
are strings. It's a free form dictionary, that allows users to store
arbitrary data.

There are however some recommended fields:

```yaml
annotations:
  io.kubewarden.policy.title: verify-image-signatures
  io.kubewarden.policy.description: A Kubewarden Policy that verifies all the signatures of the container images referenced by a Pod
  io.kubewarden.policy.author: "Raul Cabello Martin <raul.cabello@suse.com>, Victor Cuadrado Juan <vcuadradojuan@suse.de>"
  io.kubewarden.policy.url: https://github.com/kubewarden/verify-image-signatures
  io.kubewarden.policy.source: https://github.com/kubewarden/verify-image-signatures
  io.kubewarden.policy.license: Apache-2.0
  io.kubewarden.policy.usage: |
    How to use the policy
```

The `artifacthub-pkg.yml` file of the same policy has the following contents:

```yaml
---
# artifacthub-pkg.yml
version: 0.1.6
name: verify-image-signatures
displayName: Verify Image Signatures
createdAt: '2022-07-19T16:28:15+02:00'
description: A Kubewarden Policy that verifies all the signatures of the container
  images referenced by a Pod
license: Apache-2.0
homeURL: https://github.com/kubewarden/verify-image-signatures
containersImages:
- name: policy
  image: ghcr.io/kubewarden/policies/verify-image-signatures:v0.1.6
keywords:
- pod
- signature
- sigstore
- trusted
links:
- name: policy
  url: https://github.com/kubewarden/verify-image-signatures/releases/download/v0.1.6/policy.wasm
- name: source
  url: https://github.com/kubewarden/verify-image-signatures
provider:
  name: kubewarden
recommendations:
- url: https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller
annotations:
  kubewarden/resources: Pod
  kubewarden/mutation: true
  kubewarden/contextAware: false
```

> Note: the format of the `artifacthub-pkg.yml` file is described
> [here](https://github.com/artifacthub/hub/blob/master/docs/metadata/artifacthub-pkg.yml)

Some of these fields are shared by all Kubewarden policies (like `provider` and `recommendations`),
others can be obtained by looking at the contents of `metadata.yml` (like `license`, `name`
and others), while others are completely missing from the current `metadata.yml` (like
`version`, `createdAt`, `annotations.'kubewarden/resources'`).

The next section describes how we are going to extend the `metadata.yml` file
to allow the creation of `artifacthub-pkg.yml` file from its contents.

## Creating `artifacthub-pkg.yml` from `metadata.yml`

In this section we will go over each line of the `artifacthub-pkg.yml` file
shown above and explain how we will generate it in an automatic way:

### `version`

This attribute is required by Artifact Hub:

```yaml
version: 0.1.6
```

This field does not exist inside of `metadata.yml`. For Rust policies we can obtain it
by reading the contents of `Cargo.toml`. For other languages, like Go, this information
is not available anywhere in the source code. Hence this must be specified via a
cli flag of `kwctl scaffold artifacthub`.

> **Note:** we could use the current git tag to infer the version of the policy. However
> this would not work in our case, because the workflow to release a new policy is:
>   1. Update `metadata.yml` file [optional]
>   1. Generate/Update manutally `artifact-hub.yml` file
>   1. Commit changes to Git
>   1. Create a new Git tag
>
> Inferring the policy version using the latest Git tag would not give the correct
> value.

### `name`

This attribute is required by Artifact Hub:

```yaml
name: verify-image-signatures
```

This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.kubewarden.policy.title: verify-image-signatures
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. Since this is instead required by `artifacthub-pkg.yml`,
the `kwctl scaffold` will exit with a meaningful error if this annotation is not
found inside of `metadata.yml`.

### `displayName`

This attribute is required by Artifact Hub:

```yaml
displayName: Verify Image Signatures
```

This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.artifacthub.displayName: Verify Image Signatures
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. Since this is instead required by `artifacthub-pkg.yml`,
the `kwctl scaffold` will exit with a meaningful error if this annotation is not
found inside of `metadata.yml`.

### `createdAt`

This attribute is required by Artifact Hub:

```yaml
createdAt: '2022-07-19T16:28:15+02:00'
```

Moreover, this value must be updated every time a new version is released.

This value will be computed by `kwctl scaffold artifacthub` command. It will
use the current time.

### `description`

This attribute is required by Artifact Hub:

```yaml
description: A Kubewarden Policy that verifies all the signatures of the container
```

This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.kubewarden.policy.description: A Kubewarden Policy that verifies all the signatures of the container images referenced by a Pod
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. Since this is instead required by `artifacthub-pkg.yml`,
the `kwctl scaffold` will exit with a meaningful error if this annotation is not
found inside of `metadata.yml`.

### `license`

This attribute is considered optional by Artifact Hub:

```yaml
license: Apache-2.0
```

This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.kubewarden.policy.license: Apache-2.0
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. This value is not required by `artifacthub-pkg.yml`,
hence `kwctl scaffold` not fail if this annotation is not found inside of `metadata.yml`.

### `homeURL`

This attribute is considered optional by Artifact Hub:

```yaml
homeURL: https://github.com/kubewarden/verify-image-signatures
```

This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.kubewarden.policy.url: https://github.com/kubewarden/verify-image-signatures
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. This value is not required by `artifacthub-pkg.yml`,
hence `kwctl scaffold` not fail if this annotation is not found inside of `metadata.yml`.

### `containersImages`

This attribute is considered optional for general Artifact Hub packages. Yet
for Kubewarden policy packages in Artifact Hub it is
[mandatory to have a container image with name "policy"](https://artifacthub.io/docs/topics/repositories/kubewarden-policies):

```yaml
containersImages:
- name: policy
  image: ghcr.io/kubewarden/policies/verify-image-signatures:v0.1.6
```

This value is partially hard coded (the `name` must be `policy` for some
Artifact Hub "magic" to work). The `image` name will be computed starting
from the `version` attribute (see above) and the following annotation of
`metadata.yml`:

```yaml
annotations:
  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/verify-image-signature
```

The final url will be built using this format:

```rust
let url = format!("{}:v{}", ociUrl, version);
```

This assumes the final tag will follow this naming convention: `v{version}`.

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. Since this is instead required by `artifacthub-pkg.yml`,
the `kwctl scaffold` will exit with a meaningful error if this annotation is not
found inside of `metadata.yml`.

### keywords

This attribute is considered optional by Artifact Hub:

```yaml
keywords:
- pod
- signature
- sigstore
- trusted
```

This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.artifacthub.keywords: "pod, signature, sigstore, trusted"
```

Given `annotations` is a map with both keys and values being strings, we have to join
the keywords using the `,` symbol.

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. This value is not required by `artifacthub-pkg.yml`,
hence `kwctl scaffold` not fail if this annotation is not found inside of `metadata.yml`.

### `links`

This attribute is considered optional by Artifact Hub:

```yaml
links:
- name: policy
  url: https://github.com/kubewarden/verify-image-signatures/releases/download/v0.1.6/policy.wasm
- name: source
  url: https://github.com/kubewarden/verify-image-signatures
```

The link pointing to the `wasm` module file is going to be computed when the 
value of the `io.kubewarden.policy.source` indicates that the policy is hosted on GitHub.
We will assume the `.wasm` policy is released at the following url:

```rust
let url = format!("{}/releases/download/v{}/policy.wasm", sourceUrl, version);
```
Instead, the value of the `source` link is going to be built using the
following annotation:

```yaml
annotations:
  io.kubewarden.policy.source: https://github.com/kubewarden/verify-image-signatures
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. This value is not required by `artifacthub-pkg.yml`,
hence `kwctl scaffold` not fail if this annotation is not found inside of `metadata.yml`.

### Hard coded values

There are some values that are going to be always the same, regardless of the policy and
its version:

```yaml
provider:
  name: kubewarden
recommendations:
- url: https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller
```

These values are going to be hard coded inside of kwctl.

### Kubewarden specific annotations``

The `artifacthub-pkg.yml` has its own `annotations` field. This is optional and
is a dictionary with strings both keys and values.

We are always going to have this data inside of it, since it comes from
values that are mandatory inside of `metadata.yml`:

```yaml
annotations:
  kubewarden/mutation: true
  kubewarden/contextAware: false
```

These value will be taken from the following keys of `metadata.yml`:

```yaml
mutating: true
contextAware: false
```

We are also going to attempt to create the following annotation inside of `artifacthub-pkg.yml`:

```yaml
annotations:
  kubewarden/resources: Pod, Deployment
```
This is going to be created by copying the value of this `metadata.yml` annotation:

```yaml
annotations:
  io.artifacthub.resources: Pod, Deployment
```

## Consume projects' `README.md`

Currently the `metadata.yml` has this optional annotation:

```yaml
annotations:
  io.kubewarden.policy.usage: |
    How to use the policy
```

The contents of this annotation is super long, and is basically a 1:1 copy of the `README.md` found
inside of the root of the project.

Keeping this annotation in sync is ugly, plus it makes the whole `metadata.yml` uglier.

I propose to change the `kwctl annotate` command to have another extra flag called `usage`. When provided,
the contents of the `io.kubewarden.policy.usage` will be read from the file pointed by the `usage` flag.

For example:

```console
kwctl annotate -m metadata.yml --usage README.md -o annotated.wasm policy.wasm
```

## Web UI questions

The Web UI we're currently developing can use a special `question.yml` file to
programmatically generate the configuration UI of a policy.

We plan to add the contents of this file inside of the `artifacthub-pkg.yml` file, under
the following annotation:


```yaml
annotations:
  kubewarden/questions-ui: |
    <a YAML document>
```

Having this annotation is entirely optional.

We envision the following workflow for the policies that want to have the web UI
provide a better UX:

* The user will maintain the configuration directives inside of a `questions-ui.yml` file.
  Just as a reference, the contents of this file are goint to be similar to
  [this one](https://github.com/kubewarden/ui/blob/7461055e54053db7bcbf696d2e16c8a690f9399c/pkg/kubewarden/questions/policy-questions/allow-privilege-escalation-psp.yml)
* The `kwctl scaffold artifacthub` command will feature a flag called `questions-ui` which can be
  used to point to the `questions-ui.yml` file
* As a result, the generated `artifacthub-pkg.yml` file will have the `kubewarden/questions-ui` annotation


### Hidden-UI

The Web Ui we're currently developing can decide to show or not the specific
policy. This can be configured by passing the following annotation inside
`artifacthub-pkg.yml`:

```yaml
annotations:
  rancher/hidden-ui: true
```


This value will be taken from the following annotation of `metadata.yml`:

```yaml
annotations:
  io.rancher.hidden-ui: true
```

Given all the annotations inside of `metadata.yml` are optional, the `metadata.yml`
file might be missing this value. This value is not required by `artifacthub-pkg.yml`,
hence `kwctl scaffold` not fail if this annotation is not found inside of `metadata.yml`.

## Implementation details

We plan to implement this new code using vanilla Rust inside of `policy-evaluator`. This is the
crate where the `metadata.yml` code currently lives.

We plan to create a `ArtifactHubPkg` structure that can be used to produce (via serde serialize) the
`artifacthub-pkg.yml` file.

The `kwctl scaffold artifacthub` code will read the `metadata.yml` file into a `Metadata` instance.
Then it will create a `ArtifactHubPkg` instance using a constructor that will have a signature similar
to the following one:

```rust
impl ArtifactHubPkg {
  pub fn from_metadata(metadata: &Metadata, version: &str) -> Result<Self>;
}
```

# Drawbacks

## Writing too much Rust code

Doing all the transformation from one configuration format (`metadata.yml`) using
vanilla rust require some boilerplate to be written:

* Some new Rust structs
* Initialization code

This could be simplified by using, behind the scenes, something like [jsonnet](https://jsonnet.org).

We've successfully done a POC that works this way:

* All the policy metadata is stored into a `libsonnet` file, which is a superset of JSON
* The `metadata.yml` and `artifacthub-pkg.yml` files can be generated using jsonnet transformations

The jsonnet transformations are written inside of a `.jsonnet` file. This file is shared by
all the policies. This file should not be duplicated inside of each policy repository, otherwise
propagating changes to it would be extremely painful.

Moreover, jsonnet would require some external parameters to be provided at run time: `version` and
`createdAt`.

Long story short, we could embed the contents of `.jsonnet` file inside of the `kwctl` binary, and then
use a jsonnet rust library to perform the transformation.

However these has the following drawbacks:

* Currently all the rust libraries of jsonnet seem to rely on the CPP bindings of libjsonnet. Which makes
  extremely hard to build a statically linked binary of kwctl. There's actually an open issue for that.
* We lose the safety of Rust types

## Too much usage of annotations inside of `metadata.yml`

The annotations inside of `metadata.yml` are deliberately free form. The Rust structure that
defines `Metadata` implements them using a `HashMap<String, String>`.

This means that there's no well defined Rust attribute for some of the mandatory annotations that
`artifacthub-pkg.yml` requires.
That makes deserialization/transformation/serialization and checks more verbose.

Another possible solution would be to create a new "umbrella" configuration file that is then transformed
into the `metadata.yml` and the `artifact-hub.yml` file.

This is how the "umbrella config" might look like. This example is written using the `jsonnet` format,
which is a superset of JSON. However we could use any other kind of format:

```jsonnet
{
  name: 'verify-image-signatures',
  displayName: 'Verify Image Signatures',
  description: 'A Kubewarden Policy that verifies all the signatures of the container images referenced by a Pod',
  keywords: [
    'pod',
    'signature',
    'sigstore',
    'trusted',
  ],
  authors: [
    'Raul Cabello Martin <raul.cabello@suse.com>',
    'Victor Cuadrado Juan <vcuadradojuan@suse.de>',
  ],
  homeURL: 'https://github.com/kubewarden/verify-image-signatures',
  sourceURL: 'https://github.com/kubewarden/verify-image-signatures',
  ociURL: 'ghcr.io/kubewarden/policies/verify-image-signatures',
  license: 'Apache-2.0',
  rules: [
    {
      apiGroups: [''],
      apiVersions: ['v1'],
      resources: ['pods'],
      operations: ['CREATE', 'UPDATE'],
    },
  ],
  resources: [
    'Pod',
    'Deployment',
  ],
  mutating: true,
  contextAware: false,
  executionMode: 'kubewarden-wapc',
}
```

I would like to go this way honestly. I just struggle to find a good name for this umbrella file.

We could then have these commands:

* `kwctl scaffold artifacthub`: the command describe above, but it would read data from this umbrella config instead of `metadata.yml`
* `kwctl scaffold metadata`: this could generate the `metadata.yml`  file

Another alternative might be to not implement the `kwctl scaffold metadata`, but instead change the
`kwctl annotate` command so that it can also read the values of the umbrella configuration file.

# Alternatives

## Using JSON schema

We thought about using JSON Schema to describe the format of our metadata. This is interesting, it could provide
value to our users. However it doesn't address the problem of automating the generation of
`artifacthub-pkg.yml` and `metadata.yml`.

We can revisit this topic later on.


# Unresolved questions

Should we extend the `metadata.yml` file or should we create an "umbrella" configuration file?
