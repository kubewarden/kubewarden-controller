
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

The audit checks will require changes in `PolicyServer`, policies and the creation of a new component `Background Audit Scanner`.

## Policy server

`PolicyServer` needs to store successful evaluation from all policies, and also failed evaluations for 
policies in monitor mode. Failed evaluations for policies in enforce mode will not be stored as resources won't be 
created in the cluster. These evaluations will be stored in a `PolicyReport`. There is one `PolicyReport` per namespace and 
one `ClusterPolicyReport` for cluster-wide resources, see this [RFC](https://github.com/kubewarden/rfc/pull/13/files) for more info.

Many more calls will be made to `PolicyServer` for the background checks, therefore we need to implement a cache
for policy evaluations. The result of each policy evaluation will be stored in the cache, it will contain the `resourceVersion`
of the policy and the resource to see if any of them have changed. Before evaluating a new resource it will check in the 
cache if evaluation was previously done. 

## Background Audit Scanner

By default, background audit scanning happens every hour, and it can be configured via the `background-scan` flag.
It will scan all resources in the cluster for all policies. It will perform evaluations just for the CREATE operation.
Background Audit Scanner will not perform any mutation even if the policy has mutation enabled, it will still perform 
validation for mutating policies.
When a background audit has finished processing all evaluations it will replace all `PolicyReports` and the `ClusterPolicyReport`
with the new content. This will remove old entries with resources that are deleted and make sure the reports are up to date. 

There are certain types of policies that we cannot audit in a reliable way. For example, a policy that relies on the userInfo
section of a request cannot be audited. That's because the userInfo "faked" by the audit is not going to be relevant. Operators
can disable these policies for the background check using the `backgroundAudit` field

Background Audit Scanner won't perform policy evaluation, it will make a request to `PolicyServer` for evaluating the resources
instead.

It should implement a caching mechanism to avoid overloading the Kubernetes api server. We can use client-go caching.

A background audit checks consist of the following steps:
1. Get information about which policies have audit checks enabled
2. Get the resources configured in the policies with audit checks enabled. For `AdmissionPolicies` it will check resources
within its namespace. For 'ClusterAdmissionPolicies' it will check in all the cluster or use the `namespaceSelector` filter
if present.
3. Request the policy evaluation for all resources to the `PolicyServer`
4. Aggregate all the policies validation results
5. Publish a `PolicyReport` per namespace with the aggregated results and the `ClusterPolicyReport`.

In step 2, after fetching the resources for the first time,  they will be stored in a
cache and used again in futures audit checks until the *time to live* period expired.
Triggering another request to the Kubernetes API.

## ClusterAdmissionPolicy and AdmissionPolicy CRDs

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

# Drawbacks

Both Audit Background Scanner and Policy Server must write to the same PolicyReport. It might happen that both try to
write at the same time. This will cause an error in the latest write. A retry mechanism should be implemented in the
Background Audit Scanner to handle this scenario.

No real time audit info. In future iterations Audit Scanner could be watching all resources and updating reports in real time.

Many more calls to Policy Server and the Kubernetes api server. Caching should help, but still many more calls will be made.

`PolicyReports` size could be big if there are many resources and policies in the same namespace. More info on how big it 
could be [here](https://github.com/kubewarden/rfc/pull/13#issuecomment-1253744208)

# Alternatives

## Background Auditor Scanner is only service that updates PolicyReports

PolicyServer would not store evaluations in PolicyReport. Instead, it would call the Auditor Scanner using a rest API.
This means Background Audit Scanner should always be running, and it can't be a `CronJob`.

If auditor is not available report data is lost. This data will be recovered in the next background scan.

Background Auditor Scanner is the only service writing `PolicyReports`, which makes easier to handle concurrent writes.

## Run background scan in PolicyServer

No need to create Background Auditor Scanner. Everything is done in `PolicyServer`. PolicyServer will take care 
of doing the background scan.

If background scan takes too long `PolicyServer` might be slower for evaluation requests, which would slow down creation 
of new resources in the cluster.

# Unresolved questions

Background Auditor check in a CronJob or a Pod always running?

That depends on how often we want to run the scan. If we run the scan every hour (or even more) most of the time the 
Background Auditor Check would be idle and wasting cluster resources.



