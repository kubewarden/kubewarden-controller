|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Kubernetes admission control threat model                           |
| Start Date   | 04/18/2022                          |
| Category     | Security                       |
| RFC PR       | https://github.com/kubewarden/rfc/pull/2  |
| State        | **ACCEPTED**                     |

# Summary
[summary]: #summary

Describe the threat model for the admissions control, how it can effect Kubewarden
and the possible mitigations.

# Motivation
[motivation]: #motivation

The goal of this is turn Kubewarden more secure to operate.

## Examples / User Stories
[examples]: #examples

As Kubewarden developer, I want to know which are the weak point of the Kubernetes admission control feature, so I can
mitigate this problem.

As Kubewarden user, I want to know which are the weak points of the Kubernetes admission control, so I can apply the mitigation
in my cluster.

# Detailed design
[design]: #detailed-design

The threat model of the Kubernetes admission control list 18 possible threats.
All of them will be discussed sharing a brief description of it, possible mitigation
and what we, as Kubewarden team, should do about it (if necessary). As well as
help our users to be aware of the risks.

If more details about each threat is needed, go to the original document here:
https://github.com/kubernetes/sig-security/tree/main/sig-security-docs/papers/admission-control


## Threat 1 - Attacker floods webhook with traffic preventing its operation

An attacker who has access to the Webhook endpoint, at the network level, could
send large  quantities of traffic, causing an effective denial of service to the
admission controller.

**Mitigation**

Webhook fails closed. In other words, if the webhook does not respond in time,
for any reasion, API server should reject the request. We are safe on this.
Kubewarden default behavior  already does that.

## Threat 2 - Attacker passes workloads which require complex  processing causing timeouts

An attacker, who can access the admission controller at a network level, passes
requests to  the admission controller which require complex processing, causing
timeouts as the  admission controller uses compute power to process the workloads

**Mitigation**
Webhook fail closed and authenticate callers. We are safe, Kubewarden already does that.

## Threat 3 - Attacker exploits misconfiguration of webhook to bypass
An attacker, who has rights to create workloads in the cluster, is able to exploit
a mis-configuration to bypass the intended security control

**Mitigation**
Regular reviews of webhook configuration catch issues.


### Threat 4 - Attacker has rights to delete or modify the k8s webhook  object

An attacker who has Kubernetes API access, has sufficient privileges to delete
the webhook  object in the cluster.

**Mitigation**
RBAC rights are strictly controlled.

**To do**
I think most of the RBAC is not Kubewarden responsibility. But we can help our users if we:
- Warning them in our docs and *suggest* some minimum RBAC to be used.
- Provide a policy which detect RBAC changes and **maybe** block them.


## Threat 5 - Attacker gets access to valid credentials for the webhook
An attacker gains access to valid client credentials for the admission controller webhook

**Mitigation**
Webhook fails closed.

Kubewarden is failed closed. Thus, we should be fine.

## Threat  6 - Attacker gains access to a cluster admin credential

An attacker gains access to a cluster-admin level credential in the kubernetes cluster.

**Mitigation**
N/A

I cannot see how Kubewarden can help here.

## Threat 7 - Attacker sniffs traffic on the container network
An attacker who has access to the container network is able to sniff traffic
between the API  server and the admission controller webhook.

**Mitigation**
Webhook uses TLS encryption for all traffic

Kubewarden are safe. Because the webhook connections are encrypted.


## Threat 8 - Attacker carries out a MITM attack on the webhook
An attacker on the container network, who has access to the NET_RAW capability
can  attempt to use MITM tooling to intercept traffic between the API server
and admission  controller webhook.

**Mitigation**
Webhook mTLS authentication is used.

**To do**
Kubewarden should implement mutual TLS authentication
We can add in the recommended policies from the `kubewarden-defaults` Helm
chart a policy to drop the `NET_RAW` capability.

### Threat 9 - Attacker steals traffic from the webhook via spoofing
An attacker is able to redirect traffic from the API server which is intended
for the admission  controller webhook by spoofing.

**Mitigation**
Webhook mTLS authentication is used.

**To do**
Kubewarden should implement mutual TLS authentication

### Threat 10 - Abusing a mutation rule to create a privileged container
An attacker is able to cause a mutating admission controller to modify a workload,
such that  it allows for privileged container creation

**Mitigation**
All rules are reviewed and tested.

**To do**
We may came up with some tests to cover this rules reviews
We  should carefully review a PR changing the rules in the policies deployment

## Threat 11 - Attacker deploys workloads to namespaces that are  exempt from admission control
An attacker is able to deploy workloads to Kubernetes namespaces that are exempt
from the  admission controller configuration.

**Mitigation**
RBAC rights are strictly controlled

**To do**
I think most of the RBAC is not Kubewarden responsability. But we can help our users if we:
- Warning them in our docs and *suggest* some minimum RBAC to be used.
- Provide a policy which detect RBAC changes and **maybe** block them. Is this possible?


## Threat ID 12 - Block rule can be bypassed due to missing match (e.g.  missing initcontainers)
An attacker created a workload manifest which uses a feature of the Kubernetes
API which  is not covered by the admission controller

**Mitigation**
All rules are reviewed and tested.

**To do**
We may came up with some tests to cover this rules reviews
We  should carefully review a PR changing the rules in the policies deployment

## Threat ID 13 - Attacker exploits bad string matching on a blocklist to  bypass rules
An attacker, who has rights to create workloads, bypasses a rule by exploiting
bad string  matching.

**Mitigation**
All rules are reviewed and tested.

**To do**
We may came up with some tests to cover this rules reviews
We  should carefully review a PR changing the rules in the policies deployment

## Threat ID 14 - Attacker uses new/old features of the Kubernetes API  which have no rules
An attacker, with rights to create workloads, uses new features of the Kubernetes
API (for  example a changed API version) to bypass a rule.

**Mitigation**
All rules are reviewed and tested.

**To do**
We may came up with some tests to cover this rules reviews and API versions.
We can create a configuration to reject by default requests where the API
version not cover by the policy.  We should warning policies developers to cover
all the supported API version in theirs tests and reject all of others.


## Threat ID 15 - Attacker deploys privileged container to node running  Webhook controller
An attacker, who has rights to deploy privileged containers to the cluster, creates
a privileged  container on the cluster node where the admission controller webhook operates.

**Mitigation**
Admission controller uses restrictive policies to prevent privileged  workloads

**To do**
I do not know if Kuberwarden can help on this. Kubewarden does not have access to
containers running in the cluster node.


## Threat ID 16 - Attacker mounts a privileged node hostpath allowing  modification of Webhook controller configuration
An attacker, who has rights to deploy hostPath volumes with workloads, creates a
volume  which allows for access to the admission controller pod’s files.

**Mitigation**
Admission controller uses restrictive policies to prevent privileged  workloads

**To do**
We can add a recommended policy in the `kubewarden-default` Helm chart to prevent this.


## Threat ID 17 - Attacker has privileged SSH access to cluster node  running admission webhook
An attacker is able to log into cluster nodes as a privileged user via SSH.
**Mitigation**
N/A

I don't think Kubewarden can help on this


## Threat ID 18 - Attacker uses policies to send confidential data from  admission requests to external systems
An attacker is able to configure a policy that listens to admission requests and
sends  sensitive data to an external system.

**Mitigation**
Strictly control external access for webhook

Kubewarden policies run in a restrictive environment. They do not have network access.


## Threat Kubewarden ID 1 - Bootstrapping of trust for admission controller
Assuming a trusted but fresh Kubernetes cluster, an attacker is able to compromise the Kubewarden stack before any of the policies securing it is deployed and enforcing. For example, by using unsigned and malicious images for kubewarden-controller, policy-server, or any of the Kubewarden dependencies (cert-manager) or optional dependencies (grafana, prometheus..), or by compromising the Helm charts payload.

** Mitigation **
1. Kubewarden provides a Software Bill Of Materials, which lists all images needed. This aids with Zero-Trust.
  The Kubernetes Administrator must verify the Kubewarden images (and its dependencies' images and charts) out of the Kubernetes cluster, in a trusted environment. This can be done with `cosign`, for example.
  Incidentally, this is part of the implementation needed for air-gapped installations.
 2. Use signed Helm charts, and verified digests (instead of tags) for Kubewarden images in those Helm charts. This doesn't secure dependencies though.

# Drawbacks
[drawbacks]: #drawbacks


# Alternatives
[alternatives]: #alternatives


# Unresolved questions
[unresolved]: #unresolved-questions

