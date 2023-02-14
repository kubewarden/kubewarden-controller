|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Context Aware Policies           |
| Start Date   | 13-02-2023                       |
| Category     | [Category]                       |
| RFC PR       | [fill this in after opening PR]  |
| State        | **ACCEPTED**                         |


# Summary
[summary]: #summary

Define how policies can obtain additional information from Kubernetes API server
at evaluation time.

# Motivation
[motivation]: #motivation

In certain cases a policy requires additional information about the state of the
Kubernetes cluster in order to take a validation decision.
These kind of policies are called "context aware". 

Kubewarden must allow policy authors to write context aware policies. At
the same time, we must prevent rogue policies to perform abuses against the
cluster.

## Examples / User Stories
[examples]: #examples

> As a Policy author,
> I want to obtain a list of all the other Ingress objects
> defined inside of the cluster in order to accept or reject the
> creation of another Ingress object.

> As a Kubernetes administrator,
> I want to know what kind of Kubernetes resources a policy can
> query at evaluation time.

> As a Kubernetes administrator,
> I want context-aware policies to be able to access only the list
> of Kubernetes resources that the policy author declared.
> Attempts to access other types of resources should be blocked and
> reported to me.

# Detailed design
[design]: #detailed-design

Kubewarden currently features a prototype implementation of context aware policies.
This implementation is limited and this RFC plans to entirely replace it.

Currently we are not aware of any policy making use of this implementation.

## Policy metadata

Context aware policies must mention explicitly the types of
Kubernetes resources they are going to access at evaluation time.

This is required to provide transparency to the Kubernetes administrator who
will deploy the policy.

Policy author must mention the Kubernetes resources inside of the policy
metadata:

```yaml
contextAware:
# - group: <group>
#   version: <version>
#   resource: <resource>
- version: v1
  resource: pods
- group: apps
  version: v1
  resource: deployments
- group: networking.k8s.io
  version: v1
  resource: ingresses
```

These values can be obtained by looking at the output of `kubectl api-resources`.

This information is then embedded into the policy by using the `kwctl annotate`
command.

## Policy Deployment

When deploying the policy, the Policy Server will by default block access to all
Kubernetes resources. Kubernetes administrator have to explicitly opts in, on a
per policy basis.

This is done for security reasons. We don't want an attacker to steal sensitive
information from a Kubernetes cluster by leveraging a Kubewarden policy.

The `ClusterAdmissionPolicy` Custom Resource Definition is going to be extended
to include a new `contextAware` field that holds a list of
`group-version-resource` items:

```yaml
contextAware:
# - group: <group>
#   version: <version>
#   resource: <resource>
- version: v1
  resource: pods
- group: apps
  version: v1
  resource: deployments
- group: networking.k8s.io
  version: v1
  resource: ingresses
```

To keep things simple, this is the same format used inside of the policy metadata.

> **Note:** in the beginning, only `ClusterAdmissionPolicy` resources are going
> to support context-aware policies. This won't apply to `AdmissionPolicy`
> resources. More on that later.

This information will be be propagated by the Kubewarden controller to the Policy
Server `policies.yml` file:

```yaml
namespace-validate:
  url: file:///tmp/namespace-validate-policy.wasm
  allowedToMutate: false
  contextAware:
  # - group: <group>
  #   version: <version>
  #   resource: <resource>
  - version: v1
    resource: pods
  - group: apps
    version: v1
    resource: deployments
  - group: networking.k8s.io
    version: v1
    resource: ingresses
  settings:
    valid_namespace: valid
```

To summarize, Kubernetes administrators have to provide an allow list of
Kubernetes resources that each policy is allowed to have access to.
Access to resources not on this list is going to be denied by Policy Server
and reported to the administrator.

## Security Implications

Context aware policies will be granted only READ access to the cluster.

### Allow list

By default access to Kubernetes resources is denied by the Policy Server. Each
policy can have its own dedicated allow list that makes explicit the kind of
resources that can be accessed.

During its lifetime, a policy can change the types of resources it needs access
to. Adding new resources will require the Kubernetes administrator to extend the
allow list defined at deployment time.

This is done on purpose, to prevent policies to silently elevate their
visibility inside of the cluster during version updates.

### Resource visibility

All the queries against the API Server are performed using the
Service Account associated with the Policy Server that hosts the policy.

This allows Kubernetes administrators to use regular RBAC policies to
define what policies can access inside of the cluster.

### `AdmissionPolicy` policies

Kubewarden provides `AdmissionPolicy`, a namespaced resource that can be deployed
by unprivileged users of the Kubernetes cluster.

These policies can be hosted by a Policy Server that, given it's running with
its own dedicated Service Account, can have broader visibility inside of the
cluster compared to the user who created the `AdmissionPolicy`.

We don't want an attacker to leverage `AdmissionPolicy` resources to gain
access to confidential resources (for example, access a `Secret` owned by
a Kubernetes service or another tenant).

The `AdmissionPolicy` CRD will **not** have the `contextAware` field. Because of
that, these policies will not have the `contextAware` section inside of the
`policies.yml` file used by Policy Server (see previous section).

As a consequence, `AdmissionPolicy` instances will have an empty allow list
inside of Policy Server. Any kind of access to Kubernetes resources will
immediately be blocked and reported to the Kubernetes administrator.

# Drawbacks
[drawbacks]: #drawbacks

## Increased verbosity

To keep security high, we force Kubernetes administrators to be explicit
about the Kubernetes resources accessed by each context aware policy.
This can be tedious for the end user.

We will mitigate that by having `kwctl scaffold` handle the creation
of this new field of the `ClusterAdmissionPolicy` policy.

## `AdmissionPolicy` cannot be context-aware

This limitation is imposed to avoid attackers to extend their visibility into
the cluster by abusing the privileges granted to the Service Account used
by Policy Server.

It's not yet clear if there are real use cases for context-aware policies
being deployed as `AdmissionPolicy` instead of `ClusterAdmissionPolicy`.

We can address this limitation later on. A possibility would be to run these
`AdmissionPolicy` objects on a dedicated `PolicServer` that is deployed into
the very same Namespace of the `AdmissionPolicy`. This would cause the Policy
Server to use the same Service Account of the user creating the `AdmissionPolicy`.

# Alternatives
[alternatives]: #alternatives

We could use an approach similar to the one of Gatekeeper: Policy Server could
be configured to fetch a list of Kubernetes resources and expose that to all the
policies it hosts.

> **Note:** this is similar to what we are currently doing, except we have a hard
> coded list of of resources being mapped. We do not allow Kubernetes 
> administrators to decide what is "mirrored".

The security of this approach is inferior to the one proposed by this RFC:

* It's not clear what a policy will access at evaluation time, unless the source
  code of the policy is audited
* All the policies have access to the same set of resources. This could lead to
  leak sensitive information to other policies. For example, if a trusted policy
  requires access to Secret resources, all the other hosted policies will
  automatically gain access to this type of resources too.

# Unresolved questions
[unresolved]: #unresolved-questions

This RFC does not cover the following details:

* The waPC protocol used to exchange information between the guest and the hosted
* The caching mechanism used by Policy Server to store these information
