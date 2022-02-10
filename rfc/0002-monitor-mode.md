|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Monitor Mode                     |
| Start Date   | Nov 25th 2021                    |
| Category     | Policy Enforcement               |
| RFC PR       | [PR128](https://github.com/kubewarden/kubewarden-controller/pull/128)  |

# Summary
[summary]: #summary

> Brief (one-paragraph) explanation of the feature.

The monitor mode will improve the visibility of a cluster administrator with regards to policies and
how they act. It will enable the cluster administrator to understand the consequences of fully
activating a policy before it starts to reject requests.

# Motivation
[motivation]: #motivation

> - Why are we doing this?
> - What use cases does it support?
> - What is the expected outcome?

> Describe the problem you are trying to solve, and its constraints, without coupling them too
> closely to the solution you have > in mind. If this RFC is not accepted, the motivation can be
> used to develop alternative solutions.

Currently, Policies are deployed and become active immediately -- accepting, mutating or rejecting
requests.

With this context, as a cluster administrator it is not easy to understand the consequences of
deploying new policies in a running cluster. This RFC works on the strategy to improve this
situation and let the administrator gain visibility before policies are truly enforced in the
cluster.

Introduce a monitor mode in Kubewarden that acts in the following way:

1. Deploy policies without rejecting or mutating requests, so actions that would have been taken had
   the policy been active are logged. We will call this method "monitor"  mode, because it lets
   the cluster operator understand if a policy in this mode would be rejecting requests that impact
   the regular functionality of the cluster.

## Examples / User Stories
[examples]: #examples

> Examples of how the feature will be used. Interactions should show the action and the response.
> When appropriate, provide user stories in the form of "As a [role], I want [feature], so [that]."

As a Kubernetes administrator I want to deploy new policies in a state that they don't perform any
request rejections, but only inform about what would have been rejected had the policy been active.

As a Kubernetes administrator I want to deploy new policies in "monitor" mode, and then flip the
switch of the policy to activate it after it has been in "monitor" mode for a short while that I
considered enough to learn if it would have an undesired impact in the cluster.

As a Kubernetes administrator I want to plot in Grafana acceptions/rejections/mutations coming from
policies in "monitor" mode in the same way that I do with policies in "protect" mode -- the only mode
Kubewarden had until now.

# Detailed design
[design]: #detailed-design

> This is the bulk of the RFC. Explain the design in enough detail for somebody familiar with the
> product to understand, and for somebody familiar with the internals to implement.

> This section should cover architecture aspects and the rationale behind disruptive technical
> decisions (when applicable), as well as corner-cases and warnings.

## "monitor" mode

### CRD

The `ClusterAdmissionPolicy` CRD will be extended so it includes a `mode` attribute:

```go
type ClusterAdmissionPolicySpec struct {
   // ...
   Mode string `json:"mode,omitempty"`
   // ...
}
```

Two values are allowed: `protect` and `monitor`. If `mode` is omitted,
it will be defaulted to `protect`.

It's possible to update the `mode` from `monitor` to `protect`.

Allowing to change `mode` from `protect` to `monitor` will be rejected
-- so it's not possible to deactivate policies just by having `UPDATE`
permissions. If the user wants to change a policy from `protect` to
`monitor` mode, they have to delete the policy and recreate in `monitor`
mode as a new policy, so it's clear that the user needs `DELETE`
permission over the policy resource.

### Policy Server

The Policy Server has to be updated so the `mode` is included in the [`Policy` struct used for
settings](https://github.com/kubewarden/policy-server/blob/c8d64da87448b7f9250a1d6b5e56817f25b56359/src/settings.rs#L11-L19).

The Policy Server will always accept the request if this struct `mode` is set to `monitor`.

The Policy Server will log with INFO level every evaluation specifying the `mode` of the policy. If
the policy is mutating the resource, the resulting object will be printed in the structured tracing
output.

#### Metrics

Add `mode` to the existing `PolicyEvaluation` metric baggage.

# Drawbacks
[drawbacks]: #drawbacks

None described.

# Alternatives
[alternatives]: #alternatives

None described.

# Unresolved questions
[unresolved]: #unresolved-questions

None described.
