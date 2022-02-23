|              |                                                                       |
|:-------------|:----------------------------------------------------------------------|
| Feature Name | Policy reports                                                        |
| Start Date   | Feb 22nd 2022                                                         |
| Category     | Policy Enforcement                                                    |
| RFC PR       | [PR176](https://github.com/kubewarden/kubewarden-controller/pull/176) |

# Summary
[summary]: #summary

Policy Reports are a lightweight form of policy result reporting that
allows users to understand the impact of a policy on the cluster
without the need to deploy the whole telemetry and observability
stack.

# Motivation
[motivation]: #motivation

In order to understand how a policy behaves in a live cluster, it's
possible to relay on traces, logs and metrics of the
`policy-server`. However, if a user does not want to deploy the whole
stack -- kubewarden + observability stack --, but they still want to
have a good understanding on how a policy would behave or is behaving
in a live context, they can relay on this new feature -- Policy
Reports.

## Examples / User Stories
[examples]: #examples

> As a user testing Kubewarden, I can check in a simple and
> understandable way how a policy or set of policies behave -- what
> is/are accepting, rejecting or mutating -- just by deploying
> Kubewarden, without the need of deploying an observability stack.

> As a user that does not want to deploy the whole stack --
> kubewarden + observability stack --, I can deploy policies in
> `monitor` mode, so they don't impact my cluster behavior, and at the
> same time, check what decisions they would have taken had they been
> in `protect` mode. Only when I'm sure they won't wreak havoc in my
> cluster, I can promote them from `monitor` to `protect`.

> As a user, I am able to ask for a report of a specific policy or set
> of policies and understand how they are behaving (regardless of they
> deployment mode -- `monitor` or `protect`).

> As a user, I can check if a settings change on a policy is impacting
> the number of rejections or mutations the policy is resolving to in
> a noticeable way.

> As a user, I can understand if a policy is targeting a wider number
> of requests than it should by looking at the evaluation number
> without the need of deploying the observability stack.

> As a UI integrator, I can show rich stats about evaluations without
> the need of doing any computations, just by consuming reports, which
> have a well known, stable and versioned structure.

> As a third party integrator, the interface to fetch Kubewarden stats
> is the well known and versioned Report resource. I can use this
> information from Kubewarden to aggregate to other security relevant
> data about the cluster in a hollistic security-focused control
> plane.

> As a third party integrator, the interface to fetch Kubewarden stats
> is the well known and versioned Report resource. I can use this
> information from Kubewarden to aggregate data across different
> clusters, forming a hollistic security-focused control plane across
> clusters, giving me a rich multi-cluster security view of my
> organization in one place.

# Detailed design
[design]: #detailed-design

This is the bulk of the RFC. Explain the design in enough detail for somebody familiar with the product to understand, and for somebody familiar with the internals to implement.

This section should cover architecture aspects and the rationale behind disruptive technical decisions (when applicable), as well as corner-cases and warnings.

# Drawbacks
[drawbacks]: #drawbacks

Why should we **not** do this?

  * obscure corner cases
  * will it impact performance?
  * what other parts of the product will be affected?
  * will the solution be hard to maintain in the future?

# Alternatives
[alternatives]: #alternatives

- What other designs/options have been considered?
- What is the impact of not doing this?

# Unresolved questions
[unresolved]: #unresolved-questions

- What are the unknowns?
- What can happen if Murphy's law holds true?
