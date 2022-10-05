
|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Audit checks                           |
| Start Date   | 08/05/2022                        |
| Category     | enhancement,feature                 |
| RFC PR       | https://github.com/kubewarden/rfc/pull/10  |
| State        | **IN REVIEW**                     |


# Summary

The audit checks inspects the resources already deployed in the cluster and flags
when something violates some policies installed in the cluster.

# Motivation

Currently Kubewarden can be used to evaluate Kubernetes resources only when a relevant
operation happens: creation, update, deletion of the resource. However, policies evolve over time.
More policies can be added or they can be redeployed with different settings.
As a result of that, a Kubernetes resource that was marked as valid even a couple of hours ago,
could be instead rejected later on because of a policy change.

We want to implement a audit check that inspects all the resources that are already
present inside of the cluster and flags all the ones that are violating at least one of
the currently enforced policies.

## Examples / User Stories

As a operator, I want to know if some resource in my cluster violates the latest policies.

As a user, I want to know if some of resource that I own violates the cluster compliance policies.

As a Kubernetes developer, I want access to the audit checks results to allow me pro-grammatically act upon it.

# Detailed design

The audit check will run at specified intervals and will produce audit reports using the `PolicyReport` format.
There is going to be one `PolicyReport` object per namespace, plus one `ClusterPolicyReport` that will hold information
about the cluster-wide resources.

Details about the `PolicyReport` format can be found inside of this [RFC](https://github.com/kubewarden/rfc/pull/13/files).

## Reducing the scope to keep things simple

In the beginning we should reduce the scope of the audit checks to be able to
ship on time and iterate over the implementation by using real world data.

### No audit for policies targeting `*`

Certain policies can target any kind of Kubernetes resource. The safe
annotations policy is an example of that.

Targeting all kind of resources would make more complicated to find all the
Kubernetes resources contained inside of a Namespace that have to be audited.

To simplify things, we can state that policies targeting `*` are not going to be
evaluated by the audit checks. Users have to be explicit about the
Kubernetes resources a policy targets.

### No live update of `PolicyResult` objects

The proposed workflow requires that only one process is actively auditing the
resources of a given Namespace.

That's because:

* The `PolicyResult` of the Namespace is used to reduce the
  number of auditing evaluations performed
* Once all the policies and involved resources are audited, the
  `PolicyReport` audit is going to be overwritten with the results of the audit

Users can still get live data about the rejections/approvals by looking both
at Prometheus data and Open Telemetry traces.

We should focus on making the process of creating a `PolicyReport` as fast as
possible. The reports are recreated on a regular basis. If a user wants a fresh
`PolicyReport` without having to wait for the next scheduled run, we can
provide a way for the user to trigger this operation.

Finally, if we really have to implement live update of `PolicyReport`, we can
come up with an alternative architecture that will allow for that. For example,
we could have all the write operations of `PolicyReport` to go through a
dedicated "writer" service.

## Creating a `PolicyReport` object

The following section describes how, given a Namespace, we will produce a `PolicyReport` describing the compliance status.

The process to create the `PolicyReport` for a single Namespace can be applied also to generate the `ClusterPolicyReport`, which is the one targeting only cluster-wide resources.

### Step 1: create association between `ClusterAdmissionPolicy` and namespaces

`ClusterAdmissionPolicy` by default inspect events happening inside of all the namespaces, however users can limit their scope
by using the `spec.namespaceSelector` field.

We need to create a dictionary that holds the following information:

  * key: name of the `ClusterAdmissionPolicy`
  * value: a list containing the names of the namespaces that are relevant to the `ClusterAdmissionPolicy`

This operation can be done by iterating over each `ClusterAdmissionPolicy` and
performing a "list namespaces" query against the API server that uses the
same filter specified by the `ClusterAdmissionPolicy`.

### Step 2: find relevant policies

Given a Namespace to be audited, create a list of all the policies that are interested about the Namespace.

All the `AdmissionPolicy` resources that are defined inside of the namespace are part of the list.

For `ClusterAdmissionPolicy` resources, use the information stored inside of the
dictionary that was created during the previous step.

> Note: we will consider only policies that inspect `CREATE` events

### Step 3: find the relevant Kubernetes resources

Now we have a list of all the policies that are interested about the Namespace being audited.
We iterate over each one of them and create a dictionary that has:

* Key: the Kubernetes resource type, for example `Pod`
* Value: a list of policies that evaluate the given Kubernetes resource

The idea is to have a map of policies that tell us these information:

* `Pod` resources are relevant to `polA`, `polB`
* `Deployment` resources are relevant to `polA`
* `Ingress` resources are relevant to `polC`

### Step 4: fetch Kubernetes resources to be audited

Next we iterate over the keys of this dictionary and, for each one of them we
query the API server to get all the resources of type `X` defined inside of our Namespace.

For example, given the previous example, we would end up with:

* List of all the `Pod` objects defined inside of the audited Namespace
* List of all the `Deployment` objects defined inside of the audited Namespace
* List of all the `Ingress` objects defined inside of the audited Namespace

**Note:** there's no need to do any caching of the response we get from the Kubernetes API server because of the following reasons:

* We work on a per Namespace basis, these query results are useful only in the context of the Namespace being audited
* The audit reports is generated every X minutes (maybe 10/30/60 minutes), cached data would be useless after this time

### Step 5: attempt to reuse previous evaluation results

Now we have a these information:

* List of policies interested by a certain type of Kubernetes resource, like `Pod`
* List of Kubernetes resources, `Pod` in this case, defined inside of the Namespace we are auditing

The code will then retrieve the `PolicyReport` for the namespace being audited.

We now iterate over each resource, for example over each `Pod` resource defined
inside of the Namespace, and perform the following operations:

* Iterate over all the policies that are interested in `Pod` resources, for
  each tuple of (policy `X`, pod instance `Y`):
  * Look into the `PolicyReport` for an entry that features policy `X`
    evaluating pod instance `Y`:
    * If there's an entry, look at the evaluation timestamp of this entry.
      If policy update timestamp **and** pod instance update timestamp are older
      than the evaluation timestamp it means that nothing changed. Hence we are
      going to reuse the old evaluation result. Otherwise something changed,
      hence we **might** need to perform an evaluation.
    * If there's no entry we **might** perform an evaluation
  * If we reached this stage, it means the pod instance `Y` might need to be
    evaluated by policy `X`. We have to check the `spec.ObjectSelector` field
    defined inside of the policy (this applies both to `ClusterAdmissionPolicy`
    and to `AdmissionPolicy`) and figure out if the `ObjectSelector` is
    compatible with the pod instance `Y`. If that's true, we are going to
    perform the actual evaluation

Once the outer loop is done (the one against all the Kubernetes resources defined
inside of the audited Namespace that are affected by policies), our code will
have all the data needed to create the `PolicyReport` for the namespace being
audited.

### Step 5.5: perform evaluations

In the previous section, we saw how sometimes we need to perform a policy evaluation.

The evaluation happens by creating a fake `CREATE` event that has the Kubernetes
object being audited as `request.object`.

As a first approach, we will perform this evaluation by making an HTTP request
against the actual Policy Server that is running the policy.

We will extend Policy Server to have a new endpoint for the audit checks.
While the Kubernetes API server uses `/validate/POL_ID`, the audit scanner
will file its requests against `/audit/POL_ID` endpoint.

The `/audit` endpoint will be different from the `/validate` one in these regards:

* Generate different Prometheus metrics: we don't want the overall
  `/validate` metrics to be polluted by the audit checks
* Generate different Open Telemetry traces: again, these should not be mixed
  with the `/validate` ones. We might even want to turn them off to make the
  audit execution faster
* Policies in `monitor` mode should still behave like the ones in `protect`
  mode. They have to produce rejections if needed

By issuing the audit request against a real Policy Server, we solve these problems:

* Policies can be hosted on registries secured with credentials. We don't have
  to worry about being able to fetch the WebAssembly modules from these
  authenticated registries
* Policies might be hosted on insecure registires/registires with custom TLS
  certificates. Again, we won't have to bother about that
* Some data used by the policy (like external OCI manifests, sigstore
  verification results) can be cached by the Policy Server and reused between
  the audit evaluations and the regular validations requests

Sending all our auditing requests to the actual Policy Server could lead to poor
performance of the regular admission requests.
Currently, based on our load testing data, one single Policy Server running with
2 workers can evaluate about 1600 requests per second.
Based on this data, we think the requests generated by the audit checks should
not clog the Policy Server.
If that turns out to be true, we can embrace different strategies to mitigate
that.

Until we have real world data, it's not useful to eagerly optimize this aspect.

### Step 6: write `PolicyReport`

The code will overwrite the old `PolicyReport` instance with a new generated
from the data kept in memory. By doing that, we don't have to worry about
synchronizing the old contents with the new ones.

## Changes to Policy Server

A new rest API endpoint is going to be created called `/audit`.

The endpoint will receive POST requests similar to the ones generated by the
Kubernetes API server.

All the policies hosted by the Policy Server will be exposed via `/audit/POL_ID`
endpoints.

The `/audit` API will behave in a slightly different way compared to the current `/validate`
endpoint. The differences have been illustrated by the previous section of things
RFC.

## Changes to ClusterAdmissionPolicy and AdmissionPolicy CRDs

It's necessary a change in the policy CRDs to mark a policy to be run in the background audit checks.
The field would be called `backgroundAudit` and its default value will be `true`.
Therefore, all the policies will run in the audit checks by default, unless the user
configure the other way. Example of policies CRDs with the `backgroundAudit` field:

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
  backgroundAudit: true
  settings:
    allowed_capabilities:
    - CHOWN
    required_drop_capabilities:
    - NET_ADMIN
```

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: AdmissionPolicy
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
  backgroundAudit: true
  settings:
    allowed_capabilities:
    - CHOWN
    required_drop_capabilities:
    - NET_ADMIN
```

## Background Audit Scanner

This is a new component that implements the algorithm described before to create
all the `PolicyReport` objects and the `ClusterPolicyReport` one.

The audit scanner is a CLI program running in a non interactive way. It will be
ran via a Kubernetes CronJob every 30 minutes. In the future we can provide a
way to allow the user to configure this interval.

In the initial version, the scanner will iterate sequentially over each namespace
to generate its `PolicyReport` object. In the future we might want to change
this implementation to scan the namespaces in parallel.

By default, the scanner will look at all the namespaces defined inside of the
cluster. We might want to add a cli flag and environment variable that allows
the user to explicitly pick the namespaces to inspect. This could be used to
provide a way to our user to generate the audit report of a specified namespace
on demand, without having to wait for the next run on the scanner.


# Drawbacks

No real time audit info are provided by this solution. Users have to rely on
Prometheus metrics and Open Telemetry trace events to have live data coming
from the cluster.

We might want to address this limitation in the future by introducing a more
complex architecture.

`PolicyReports` size could be big if there are many resources and policies in the same namespace. More info on how big it 
could be [here](https://github.com/kubewarden/rfc/pull/13#issuecomment-1253744208)

# Alternatives

## Introduce `PolicyReport` writer service

Introduce a new service in charge of writing the `PolicyReport` objects.

The audit scanner would not write `PolicyReport` directly, but rather send them
to this service.

The Policy Server instances would also send the outcomes of their validations to
this service. This would allow to have live events added to the `PolicyReport`.

The main drawback of this solution is:

  * More components are running inside of the cluster, consuming resources
  * If the `PolicyReport` write service is unreachable, the existing `PolicyReport`
    are going to contain stale data or not be available

# Unresolved questions

No unresolved questions so far.
