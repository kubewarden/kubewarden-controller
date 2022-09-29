
|              |                                            |
| :----------- | :----------------------------------------- |
| Feature Name | Policy Report format audit checks          |
| Start Date   | 08/05/2022                                 |
| Category     | enhancement,feature                        |
| RFC PR       | https://github.com/kubewarden/rfc/pull/13  |
| State        | **ACCEPTED**                                   |


# Summary

Kubewarden will generate audit reports that operators can use to identify all
the resources that are violating enforced/monitoring policies.

The reports will be periodically refreshed by a background job.

> **Note:** this RFC does not focus on how these reports are created or kept updated.
> This is going to be covered by another RFC.

# Motivation

Currently Kubewarden can be used to evaluate Kubernetes resources only when a relevant
operation happens: creation, update, deletion of the resource. However, policies evolve over time.
More policies can be added or they can be redeployed with different settings.
As a result of that, a Kubernetes resource that was marked as valid even a couple of hours ago,
could be instead rejected later on because of a policy change.

We want to implement a audit check that inspects all the resources that are already
present inside of the cluster and flags all the ones that are violating at least one of
the currently enforced policies.

The results of these evaluations must be accessible by operators and end users
in an easy way.

## Examples / User Stories

As a operator, I want to know if some resource in my cluster violates the latest policies.

As a user, I want to know if some of resource that I own violates the cluster compliance policies.

As a Kubernetes developer, I want access to the audit checks results to allow me pro-grammatically act upon it.

# Detailed design

Kubewarden will generate audit reports using the
[PolicyReport](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report)
format that is standardized by the Kubernetes SIG "wg-policy".

The audit reports are defined as set of Kubernetes CRDs. The CRDs are pretty
flexible, they can be used to store audit
results from Kubernetes policy engines (like Kubewarden or Kyverno) but can
also be used to record audit results from other kind of tools (like Kubernetes
security scanning tools as Falco or Kubebench).

Kubewarden will generate one `PolicyReport` object per each Namespace found inside of
the cluster.
Plus, it will maintain one single `ClusterPolicyReport` object to keep track
of all the cluster-wide Kubernetes resources.

## Namespace report

A Namespace can be "affected" both by `ClusterAdmissionPolicy` and by `AdmissionPolicy` policies.
When auditing a Namespace, only some Kubewarden policies are going to be interested
about the events happening inside of that Namespace. In addition to that,
the same Kubernetes resource could be evaluated by multiple policies. This will
lead to several policy evaluations being performed.

The `PolicyReport` is a namespaced CR that provides these information:

* How many policy evaluations have been done during the audit run of the Namespace
* How many policy evaluations led to a resource being accepted, rejected or
  could not be performed because of an error.
  Policy failures happen when an error occurs during the policy evaluation,
  for example, because of a runtime panic
* Detailed results about all the evaluations performed. An evaluation result contains
  the following information: the policy being used, the resource that was
  evaluated, the final outcome (accept/reject/failure) and the eventual message
  returned by the policy

The `PolicyReport` of the Namespace is kept updated during the lifetime of the
cluster, meaning:

* New Policies might become "interested" about the events happening inside of
  the cluster. New evaluations results will be added to the PolicyReport
* Existing Kubernetes objects and policies can change over time: some evaluations
  could change their outcome (pass -> fail and vice versa). The evaluation results
  must reflect that
* Policies might be deleted/might be no longer "interested" about the Namespace:
  the report must be updated to not container any reference the these policies
  and their evaluation results
* Kubernetes resources might be deleted: the report must be updated to not contain
  any reference to them


**Note:** PolicyReport resources contain security/compliance information. Regular
users of the cluster should only have READ access to them. They should not be
able to create, delete or change their contents. This can be done with Kubernetes
RBAC rules.

## Cluster report

All the Kubernetes resources that are not namespaced, are going to be audited
separately.
The auditing results are going to be saved into a Custom Resource called:
`ClusterPolicyReport`.

Given `ClusterPolicyReport` has the same structure as `PolicyReport`, Kubewarden
will handle it in the same way described in the previous section.

## `PolicyReport` detailed overview

For each Namespace, Kubewarden will find all the policies that are interested
about actions happening inside of it. This is going to be a mix of
some `ClusterAdmissionPolicy` policies and all the `AdmissionPolicy` policies
that are defined inside of the Namespace.

Next, this list of policies is going to be filtered: only policies interested
in `CREATE` events are going to be considered.
The audit report is not going to simulate `DELETE` and `UPDATE` events.

For each relevant policy, Kubewarden will find all the Kubernetes resources that
are 1) defined inside of the Namespace and 2) are relevant to the policy. Kubewarden
will then simulate the `CREATE` event of this resource and keep track of the policy
evaluation result.

All the results are going to be collected into the `PolicyReport` object defined
inside of the Namespace. There's going to be only one `PolicyReport` per Namespace.

The `PolicyReport` resource has the following fields:

* `apiVersion` and `kind`: these are defined by the CRDs
* `metadata`: this is the usual `meta/v1.ObjectMeta` resource. In the
  beginning we will set only the `name` field. We will do that by using the
  following pattern: `polr-ns-<namespace name>`
* `scope`: this is a `core/v1.ObjectReference` resource. We will use that to
  reference the Kubernetes Namespace resource that has been analyzed
* `scopeSelector`: we will not use that, because we are using the `scope` field
* `summary`: this is an object defined by a CRD `PolicyReportSummary`. It's made
  of the following fields:
  * `pass`: count of policies whose requirements were met
  * `fail`: count of policies whose requirements were not met
  * `warn:`: we will not set it, it doesn't relate to us
  * `error`: count of policies that could not be evaluated.
    The policies could not be evaluated because of errors
    (for example: a runtime panic of a broken policy)
  * `skip`: count of policies that were not selected for evaluation.
    We will allow some policies to be excluded from the background checks, more
    on that later.
* `results` this probably the most important field. It's a list of `PolicyReportResult`
  objects

The structure of the `PolicyReportResult` is flexible. This is how we are going
to use its fields:

* `source`: identifier for the policy engine that manages this report. We will
  set that to be `kubewarden`
* `policy`: this is the name of the policy that evaluated the resource. This
  could be both a `ClusterAdmissionPolicy` or a `AdmissionPolicy`.
  Because of that we cannot use the name of the policy, there could be clashes
  between cluster and namespaced policy names. We will instead use the following
  convention to build the contents of this field: `<[cap|ap]>-<policy name>`.
  For example, a `ClusterAdmissionPolicy` named `provileged-containers` will
  be identified via `cap-privileged-containers`. On the other hand, a `AdmissionPolicy`
  called `required-labels` will be identified via `ap-required-labels`.
* `rule`, `category`, `severity`, `scored`: we are going to leave these fields empty
  because they do not relate to concepts we have
* `timestamp`: the time the result was found
* `result`: this is a string enum. These are the values we will be using:
  `pass`, `fail` and `error`
* `resources`: this is a list of `core/v1.ObjectReference` objects. We will
  put only one object reference inside of this list. This is going to be a
  reference to the resource that has been analyzed by the policy
* `resourceSelector`: we are not going to use it, because we are using the `resources` field
* `message`: this is used when the policy result is `fail` or `error`. It will hold
  the output message provided by the policy
* `properties`: we are not going to use this free-form dictionary in the beginning

Let's see a concrete example about the contents of the `results` list.

Assume the following scenario:

* The Namespace being inspected contains:
  * 2 Pods
  * 1 Ingress resource
  * 1 AdmissionPolicy: `safe-labels` interested about any kind of Kubernetes resource
* 2 ClusterAdmissionPolicy are defined:
  * `privileged-containers`: interested about Pods objects
  * `ingress-lets-encrypt`: interested about Ingress objects

The policy report will have the following results:

```yaml
---
  Source:  kubewarden
  Policy:  cap-privileged-containers
  Result:  fail
  Message: privileged containers are not allowed
  Timestamp: <a timestamp>
  Resources:
    API Version: v1
    Kind:        Pod
    Name:        nginx-abuse
    Namespace:   default
    UID:         nginx-abuse-pod-uuid
---
  Source:  kubewarden
  Policy:  ap-safe-labels
  Result:  pass
  Timestamp: <a timestamp>
  Resources:
    API Version: v1
    Kind:        Pod
    Name:        nginx-abuse
    Namespace:   default
    UID:         nginx-abuse-pod-uuid
---
  Source:  kubewarden
  Policy:  cap-privileged-containers
  Result:  pass
  Timestamp: <a timestamp>
  Resources:
    API Version: v1
    Kind:        Pod
    Name:        docker-registry
    Namespace:   default
    UID:         docker-registry-pod-uuid
---
  Source:  kubewarden
  Policy:  ap-safe-labels
  Result:  fail
  Message: the `hello-world` label is not allowed
  Timestamp: <a timestamp>
  Resources:
    API Version: v1
    Kind:        Pod
    Name:        docker-registry
    Namespace:   default
    UID:         docker-registry-pod-uuid
---
  Source:  kubewarden
  Policy:  ap-safe-labels
  Result:  pass
  Timestamp: <a timestamp>
  Resources:
    API Version: networking.k8s.io/v1
    Kind:        Ingress
    Name:        docker-registry
    Namespace:   default
    UID:         docker-registry-ingress-uuid
---
  Source:  kubewarden
  Policy:  cap-ingress-lets-encrypt
  Result:  fail
  Message: wrong let's encrypt configuration is being used
  Timestamp: <a timestamp>
  Resources:
    API Version: networking.k8s.io/v1
    Kind:        Ingress
    Name:        docker-registry
    Namespace:   default
    UID:         docker-registry-ingress-uuid
```

## Creating `ClusterPolicyReport` resource

The `ClusterPolicyReport` object contains audit results for all the cluster wide
Kubernetes resources.

Since Kubewarden allows this kind of resources to be inspected only by
`ClusterAdmissionPolicy` policies, the report will be built in the following way:

* Find all the `ClusterAdmissionPolicy` policies that are interested about cluster wide
  objects
* Remove from this list all the `ClusterAdmissionPolicy` that are not interested
  about `CREATE` events
* Find all the cluster wide resources that are relevant to these policies
* Evaluate the resources using the policies
* Store the evaluation results inside of the `ClusterPolicyReport` object

The CRD of `ClusterAdmissionPolicy` is basically equal to the one of `PolicyReport`.
Because of that, we will use it in the same way as described in the previous
section about `PolicyReport`.

## Changes to `ClusterAdmissionPolicy` and `AdmissionPolicy`

We will extend the `ClusterAdmissionPolicy` and `AdmissionPolicy` resources to have
a new optional field called `background`.
This field is going to hold a boolean value, which is going to be set to be `true` by default.

Policies that have `background` set to false will be ignored during the background
scans. Hence they will never show inside of the reports.

# Drawbacks

We will have just one `PolicyReport` per Namespace. Depending on the number of
policies and Kubernetes resources defined inside of the Namespace, the size of
the `policyReport.spec.results` could be significant.

This could lead to `PolicyReport` objects too bit to be stored and/or degrade
cluster performance because of the load put on ETCD.

Quoting [this section](https://etcd.io/docs/v3.5/dev-guide/limit/#request-size-limit)
of ETCD's documentation:

>etcd is designed to handle small key value pairs typical for metadata. Larger requests will work, but may increase the latency of other requests. By default, the maximum size of any request is 1.5 MiB. This limit is configurable through --max-request-bytes flag for etcd server

# Alternatives

Instead of using the `PolicyReport` CRDs, we could adopt the same approach used
by Gatekeeper [audit feature](https://open-policy-agent.github.io/gatekeeper/website/docs/audit/#constraint-status).

Gatekeeper stores the report results inside of our equivalent of
`AdmissionPolicy` and `ClusterAdmissionPolicy` objects.

We could store the violation details inside of the `status` field of each
`AdmissionPolicy` and `ClusterAdmissionPolicy`.

Only the most recent audit runs are kept. There's also a limit on the number of
detailed reports added to a policy. This is done to prevent the clogging of ETCD,
as described in the "Drawbacks" section above.

The main limitation about this approach is not going to be able to reuse the
tool that is going to be built around the `PolicyReport` CRDs.

# Unresolved questions

How to keep the `PolicyReport`s and `ClusterPolicyReport` up to date. This is
going to be covered by another RFC.
