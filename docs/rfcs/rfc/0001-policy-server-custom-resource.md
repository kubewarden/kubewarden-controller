|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | policy-server custom resource    |
| Start Date   | Jul 22nd 2021                    |
| Category     | Architecture                     |
| RFC PR       | [fill this in after opening PR]  |

# Summary
[summary]: #summary

> Brief (one-paragraph) explanation of the feature.

Introduce a `PolicyServer` Custom Resource definition that allow users to
describe a Policy Server deployment.

Allow `ClusterAdmissionPolicies` to target a specific PolicyServer instance.

# Motivation
[motivation]: #motivation

> - Why are we doing this?
> - What use cases does it support?
> - What is the expected outcome?

> Describe the problem you are trying to solve, and its constraints, without coupling them too closely to the solution you have in mind. If this RFC is not accepted, the motivation can be used to develop alternative solutions.

Currently the Kubewarden controller deploys a single Deployment of Policy Server.
All the `ClusterAdmissionPolicies` are then evaluated by the Policy Server Pods
that belong to this Deployment.
The configuration of this Policy Server Deployment is kept inside of a ConfigMap
called `policy-server`.

Right now, the kubewarden-controller is monitoring the ClusterAdmissionPolicies
resources. Changes against these resources trigger an update of the `policy-server`
ConfigMap, and then a restart of the Policy Server Deployment.

The `policy-server` ConfigMap contains a series of configuration options related
with the Deployment (e.g.: the image to use, the size of the replica,...) and
a snapshot of the `policies.yml` file. The latter one is the file that contains
the list of policies to load, where to pull them, their configuration options,...

Currently, user-made changes to the `policy-server` ConfigMap (e.g. manual
edit via `kubectl`, or `helm upgrade`) **do not** lead to the Policy Server Deployment
to be updated.
Moreover, when changing the `policy-server` ConfigMap, the user
must be really careful to not alter the contents of the `policies.yml` key. That
can result in catastrophic outcome (all policies being dropped by the Policy Server,
leading to massive failures to all the admission reviews, leading to potential
denial of service against the Kubernetes cluster).

> **Problem #1:** provide a better UX to update the tuning
> options of the Policy Server Deployment. This must be easy and safe.

Thinking long term, there's a scalability and reliability issue with our current
architecture. All the policies are loaded by each Policy Server process. Inherently,
all the admission reviews are sent to the single deployment.

While the current setup is already HA and can be scaled by increasing the number
of replicas, there are still some hard limits and not-so-uncommon scenarios
that could lead to a service disruption:

  * Defining too many ClusterAdmissionPolicies can lead to Policy Server processes
    consuming a lot of memory and even hit resource limits
  * A "noisy" tenant/namespace or a frequently used policy can slow down policy
    evaluation and potentially bring down a Policy Server instance

> **Problem #2:** provide a way to partition policies. Allow the operator to create
> dedicated Policy Server Deployments, handling only a chosen set of policies.

This RFC aims to solve both problems.

The proposed solution is to:

  * Introduce a new Custom Resource Definition describing a PolicyServer deployment
  * Create a parent-child relationship between a PolicyServer CR and the ClusterAdmissionPolicies
    CR: one PolicyServer can have many ClusterAdmissionPolicies; a ClusterAdmissionPolicy
    belongs to one PolicyServer.

By creating a PolicyServer object we can move all the configuration details of the
Policy Server Deployment in a nicely structured place. Providing to the end
users something that is both simple and safe to edit.

This also opens the possibility to create multiple Policy Server Deployments
running on the same cluster; each one with its own dedicated configuration.

The second change, introducing a relation between ClusterAdmissionPolicy and
the freshly created PolicyServer resource, allows the Kubernetes administrators
to create Policy Server Deployments that are reserved to a subset of chosen policies.
This makes the whole infrastructure more resilient and scalable.

## Examples / User Stories
[examples]: #examples

> Examples of how the feature will be used. Interactions should show the action and the response. When appropriate, provide user stories in the form of "As a [role], I want [feature], so [that]."

As a Kubernetes Operator, I want to allocate a dedicated Policy Server Deployment,
so that "noisy" Namespaces/Tenants generating lots of policy evaluations
are isolated from the rest of the cluster and do not affect other users.

As a Kubernetes Operator, I want to allocate a dedicated Policy Server Deployment,
so that I can run mission critical policies inside of this Policy Server "pool",
making my whole infrastructure more resilient.

As a Kubernetes Operator, I want to tune the deployment settings of Policy Server,
by editing a clearly defined Custom Resource.


As a Kubernetes Operator managing multiple clusters via fleet,
I want to have a consistent setup of Kubewarden across all my clusters,
but I want to express that in an easy way,
so that I can simplify the process of maintaining the fleet configuration files.

# Detailed design
[design]: #detailed-design

> This is the bulk of the RFC. Explain the design in enough detail for somebody familiar with the product to understand, and for somebody familiar with the internals to implement.
> 
> This section should cover architecture aspects and the rationale behind disruptive technical decisions (when applicable), as well as corner-cases and warnings.

## Kubernetes Resources

A new Custom Resource is going to be defined: `PolicyServer`. This CR will
hold all the configuration details of the Policy Server Deployment.

This is just a draft proposal of the CR:

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: PolicyServer
metadata:
  name: reserved-instance-for-tenant-a
spec:
  image: ghcr.io/kubewarden/policy-server:v1.0.0
  replicaSize: 2
  sources:
    insecure:
    - insecure1.registry.foo.bar
    - insecure2.registry.foo.bar
    secure:
    - name: self-signed1.registry.com
      certificate: <base64 blob>
    - name: self-signed2.registry.com
      certificateFrom:
        configMapKeyRef:
          name: name-of-the-configmap
          key: ca_key_name
  env:
  - name: KUBEWARDEN_LOG_LEVEL
    value: debug
  - name: KUBEWARDEN_LOG_FMT
    value: jaeger
  annotations:
    sidecar.jaegertracing.io/inject: default
```

The `PolicyServer` CR will be a cluster-wide resource. Take makes each
`PolicyServer` resource identifiable by its unique `name`.

The `ClusterAdmissionPolicy` CR will be extended to have a new attribute: `policy_server`:

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: psp-capabilities
spec:
  policyServer: reserved-instance-for-tenant-a
  module: registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.3
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
      - CREATE
      - UPDATE
  mutating: true
  settings:
    allowed_capabilities:
    - CHOWN
```

The `policy_server` name identifies an existing PolicyServer object. The policy will
be served only by this PolicyServer instance.
A `ClusterAdmissionPolicy` that doesn't have an explicit `policy_server`, will
be served by the `default` one.


## Changes to the current Kubewarden controller

Currently, the Kubewarden controller watches the `ClusterAdmissionPolicy` resources.
The controller will be changed to monitor both `ClusterAdmissionPolicy` and
`PolicyServer` resources.

However, the controller will implement a reconciliation loop only for the `PolicyServer`
resource.
Whenever something happens against a `ClusterAdmissionPolicy`, the controller will
find the `PolicyServer` resource that owns it, and trigger a reconciliation event
against that `PolicyServer` instance.

The creation/update of a PolicyServer object leads to the following actions
inside of the controller:

  * List all the ClusterAdmissionPolicy resources that belong to this PolicyServer
    instance. Create/Update a ConfigMap that holds the `policies.yml` configuration.
    We could name this ConfigMap `policy-server-<name of the policy server>`.
  * Create a Deployment that runs Policy Server: use the information stored into
    the Custom Resource, plus ensure the `policy-server-<name of the policy server>`
    ConfigMap is mounted into the deployment
  * Ensure the Deployment is exposed inside of the cluster via a dedicated
    Service. We can name the service `policy-server-<name of the policy server>`
  * For each policy managed by the Policy Server, create/update the
    ValidatingWebhookConfiguration/MutatingWebhookConfiguration resources
    associated with them.

Some of the resources mentioned above are Namespace-based (like Deployment, ConfigMap, Service);
in the beginning all these resources will be created in the same Namespace where the controller
operates. We might want to make that tunable in the future, but right now it would just be
an overkill.

When a `ClusterAdmissionPolicy` resource is created/updated:

  * Find the `PolicyServer` that owns the policy
  * Trigger the reconciliation loop of the Policy Server. This will lead to an update
    of the ConfigMap that holds the `policies.yaml` file, and a rollout of the Deployment


Special handling must be done for deletion events. Both `PolicyServer` and `ClusterAdmissionPolicy`
resources must have a finalizer set.

Deletion of a `ClusterAdmissionPolicy`:

  * Thanks to the finalizer, the `ClusterAdmissionPolicy` resource is not yet deleted
    from etcd. We can hence find the `PolicyServer` that owns the about-to-be-deleted
    policy. We will use this information later on.
  * Delete the `ValidatingWebhookConfiguration` or the `MutatingWebhookConfiguration`
    resource associated with the policy.
  * Delete the `ClusterAdmissionPolicy` from etcd
  * Perform the reconciliation loop of the `PolicyServer` that owned the policy

Deletion of a `PolicyServer`:

  * Thanks to the finalizer, the `PolicyServer` resource is not yet deleted
    from etcd.
  * Go through all the policies that are owned by the `PolicyServer` instance,
    for each one of them:
    * Delete the `ValidatingWebhookConfiguration` or the `MutatingWebhookConfiguration`
      resource associated with the policy
    * Delete the `ClusterAdmissionPolicy` from etcd.
  * Delete the `PolicyServer` object from etcd

## Validation and mutation of our own Custom Resources

We must provide a mutation webhook that goes through our `PolicyServer`
and `ClusterAdmissionPolicy` objects.

This will perform the following operations:

  * `ClusterAdmissionPolicy`:
    - Set our finalizer
    - When the user specifies a value for the `policy_server` attribute, ensure
      there's actually a `PolicyServer` object with that name.
  * `PolicyServer`:
    - Set our finalizer
    - Reject the delete operations against the `PolicyServer` named `default`
    - Reject update operations that attempt to change the name of the `PolicyServer`.
      The name of a `PolicyServer` must be immutable, a lot of relationships
      between Kubernetes resources and the `PolicyServer` are built on that (for example,
      the ConfigMap, the Service, the ClusterAdmissionPolicy)

## Installation workflow

The Kubewarden stack will still be installed via helm.

The current chart is already exposing some configuration options for
the Policy Server, currently these values are put by the chart into
the `policy-server` ConfigMap.

The chart will be changed to create the `PolicyServer` named `default`.
The policy server tuning values will be used to populate the default `PolicyServer`
object instead of the `policy-server` ConfigMap.

# Drawbacks
[drawbacks]: #drawbacks

> Why should we **not** do this?
> 
>   * obscure corner cases
>   * will it impact performance?
>   * what other parts of the product will be affected?
>   * will the solution be hard to maintain in the future?

## Maintaining the PolicyServer Custom Resource

Each configuration knob of the Policy Server will have to be exposed
on the Custom Resource. This is however already happening because, while
the `policy-server` ConfigMap is kinda "free-form", we still have to
write code that fetches the right values from the ConfigMap and put them
into the Deployment definition of Policy Server.

By using a dedicated Custom Resource to define the configuration knobs of
Policy Server we will provide a better UX to our end user (as opposed to
writing key-values into a ConfigMap). However, exposing configuration knobs
will require more thinking (to find the good ergonomic) and more code to
handle that.

Let's take a look at this snippet. This exposes the contents of the `sources.yaml`
file used by Policy Server:

```yaml
  sources:
    insecure:
    - insecure1.registry.foo.bar
    - insecure2.registry.foo.bar
    secure:
    - name: self-signed1.registry.com
      certificate: <base64 blob>
    - name: self-signed2.registry.com
      certificateFrom:
        configMapKeyRef:
          name: name-of-the-configmap
          key: ca_key_name
```

The way to express self-signed registries (the `secure` section) takes
some inspiration from how Secret/ConfigMap values are mounted into
Pods. This is definitely more "Kubernetes native", but of course we will
have to define custom Structs to hold this data, and write more code
to handle them.


## Welcome back, cert-manager?

As discussed before, we must have a mutation webhook to
process `PolicyServer` and `ClusterAdmissionPolicy`
resources.

This is extremely important, because we must ensure we have
all the finalizers set and the user is not allowed harm himself
(eg: rename a PolicyServer, delete the `default` PolicyServer,...).

The controller itself can act as a mutation webhook, that's a common
practice with Kubebuilder.

However, the webhook endpoint must be secured with a TLS certificate, which
has to be somehow provided.

This is usually done by leveraging [cert-manager](https://cert-manager.io/),
which must be previously installed on the cluster.

Should we just bite the bullet and introduce this external dependency? After all,
cert-manager is already mandatory to install many other Kubernetes add-ons.

Maybe we can extend our helm chart to have these configuration knobs:

  * Install cert-manager
  * Do not install cert-manager, because it already exists. I think this
    should be the recommended option for production deployments
  * Generate the secrets via helm. This [seems doable](https://medium.com/nuvo-group-tech/move-your-certs-to-helm-4f5f61338aca).
    We would not be able to rotate them, this is definitely something for quick evaluation
    of Kubewarden. That's not meant to be used in production

However, if we introduce the cert-manager dependency, we could also leverage that to
create the certificates used by the Policy Server instances.


## Kubewarden controller developer experience

Right now, to develop the controller, we just run `make run` and that's it.

If we bring the webhook endpoint back, the local development might become more cumbersome.
This needs more research, but it's not a blocking point.

# Alternatives
[alternatives]: #alternatives

> - What other designs/options have been considered?
> - What is the impact of not doing this?

A simple approach could be to stick with the current architecture, but
perform these changes:

  * Controller: do not create the Policy Server Deployment anymore
  * Helm chart: take care of creating the Policy Server Deployment

By doing that we will have one single place where we can maintain all the Policy Server
configurations: the helm chart. Doing changes to the helm chart is definitely faster
than writing code inside of the controller.

This will potentially solve the 1st problem we have: provide a nice UX to configure
Policy Server, plus it would reduce the maintenance efforts on our side.

This wouldn't however solve the scalability and resiliency problems of Policy Server.

Last but not least, from past experience (Cloud Foundry work at SUSE, other community
projects), moving things on helm is tempting (you can go faster), but over a certain
limit this will not scale. It will become hard to maintain the helm chart and impossible
to add all the business logic you might need.

# Unresolved questions
[unresolved]: #unresolved-questions

> - What are the unknowns?
> - What can happen if Murphy's law holds true?

This architecture can provide a better UX and a more flexible, scalable and reliable
system.

However, do users of the project care about that right now? Can we go ahead with the
current architecture and just react to changes later on?

On the other hand, we are about to start working on a Rancher integration. We should build
the UI on a solid foundation. Which translates to: if we build the UI to manage the
Custom Resources defined inside of this proposal we will have a something future proof. Instead,
if we design on the current architecture we might have to change **also** the external UI code!
