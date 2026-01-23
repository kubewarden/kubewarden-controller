|              |                                           |
| :----------- | :---------------------------------------- |
| Feature Name | Policy group                              |
| Start Date   | Jun 12 2024                               |
| Category     | feature                                   |
| RFC PR       | https://github.com/kubewarden/rfc/pull/37 |
| State        | **ACCEPTED**                              |

# Summary

A "policy group" is a policy that is composed of other policies.
The policies that are part of a group are evaluated using a boolean expression.
The policy group will not support mutations.

# Motivation

[motivation]: #motivation

The motivation for this feature is to enable users to create complex policies by combining simpler ones. This allows users to avoid the need to create custom policies from scratch and instead leverage existing policies.
This reduces the need to duplicate policy logic across different policies, increases reusability, removes the cognitive load of managing complex policy logic,
and enables the creation of custom policies using a DSL-like configuration.

## Examples / User Stories

[examples]: #examples

- As a user, I want to create a policy that is composed of other policies and is evaluated using a boolean expression.
- As a user, I want to develop and test a policy group with the help of kwctl.

# Detailed design

[design]: #detailed-design

## Controller and CRDs

This RFC proposes to add two new CRDs to the Kubewarden controller:

- `AdmissionPolicyGroup`
- `ClusterAdmissionPolicyGroup`

The CRDs will share most of the fields with the `AdmissionPolicy` and `ClusterAdmissionPolicy` CRDs, respectively.
The main difference is that the `AdmissionPolicyGroup` and `ClusterAdmissionPolicyGroup` CRDs will define a list of policies.
Also, the `AdmissionPolicyGroup` and `ClusterAdmissionPolicyGroup` CRDs will have a field to specify the boolean expression that will be used to evaluate the policies
and a `message` field to specify the message that will be returned when the group policy is rejected.

### Example CRD

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicyGroup # or AdmissionPolicyGroup
metadata:
  name: pod-image-signatures
spec:
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
        - CREATE
        - UPDATE
  backgroundAudit: true
  policies:
    sigstore_pgp:
      module: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.8
      settings:
        signatures:
          - image: "*"
            pubKeys:
              - "-----BEGIN PUBLIC KEY-----xxxxx-----END PUBLIC KEY-----"
              - "-----BEGIN PUBLIC KEY-----xxxxx-----END PUBLIC KEY-----"
    sigstore_gh_action:
      module: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.8
      settings:
        signatures:
          - image: "*"
            githubActions:
              owner: "kubewarden"
    reject_latest_tag:
      module: ghcr.io/kubewarden/policies/trusted-repos-policy:v0.1.12
      settings:
        tags:
          reject:
            - latest
  expression: "sigstore_pgp() || (sigstore_gh_action() && reject_latest_tag())"
  message: "The policy group is rejected."
```

### Audit

Similar to the `AdmissionPolicy` and `ClusterAdmissionPolicy` CRDs, the `backgroundAudit` field will be used to specify if the policy group should be used or skipped when performing audit checks.

### Context-aware rules

The `AdmissionPolicyGroup` and `ClusterAdmissionPolicyGroup` CRDs support [context-aware](https://docs.kubewarden.io/reference/spec/context-aware-policies) capabilities.
Each policy in a group will accept an optional [contextAwareResources](https://docs.kubewarden.io/reference/CRDs#contextawareresource) field to specify the resources that the policy is allowed to access at evaluation time.

Example:

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicyGroup # or AdmissionPolicyGroup
metadata:
  name: context-aware-group
spec:
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
        - CREATE
        - UPDATE
  policies:
    policy_1:
      module: ghcr.io/kubewarden/policies/policy_1:v0.1.0
      contextAwareResources:
        - apiVersion: "v1"
          kind: "Pod"
      settings:
        foo: "bar"
    policy_2:
      module: ghcr.io/kubewarden/policies/policy_2:v0.1.0
      contextAwareResources:
        - apiVersion: "v1"
          kind: "Namespace"
      settings:
        foo: "bar"
  expression: "policy_1() && policy_2()"
  message: "The policy group is rejected."
```

### Expression language

We will use [CEL](https://github.com/google/cel-go) as the expression language for the policy groups.
The main reason for this choice is that CEL is used by the [ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) and [matchConditions](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-matchconditions) in Kubernetes.

Each policy in the group will be represented as a function call in the expression with the same name as the policy defined in the group.
The expression field should be a valid CEL expression that evaluates to a boolean value and it will be validated by the Kubewarden controller's webhook.
If the expression evaluates to `true`, the group policy will be considered as `accepted`, otherwise, it will be considered as `rejected`.
Also, the webhook will reject expressions where the combined policies are targeting different resources.
For example, `policy_that_eval_ingress() && policy_that_eval_pods()` is not allowed.

### Message

The message field will be used to specify the message that will be returned when the policy group is rejected.
The specific policy results will be returned in the `warning` field of the response.

This is an example of the response that will be returned when the policy group is rejected:

```json
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "<value from request.uid>",
    "allowed": false,
    "warning": [
      "sigstore_pgp was rejected: the image signature is not valid",
      "sigstore_gh_action was accepted",
      "latest_tag was rejected: the image tag latest is not allowed"
    ]
  }
}
```

### Reconciliation

The new CRDs will be reconciled by the Kubewarden controller.
The reconciliation flow is similar to the one used for the `AdmissionPolicy` and `ClusterAdmissionPolicy` resources:

- when a new `AdmissionPolicyGroup` or `ClusterAdmissionPolicyGroup` is created or updated the reconciler changes the configuration of the policy server to include the created/updated policy group
- the reconciler rolls out the policy server deployment
- the reconciler creates or updates the ValidatingWebhookConfiguration pointing to the policy server `validate` endpoint of the policy group

### Match Conditions

An interesting use case is to use the policy groups in combination with the [matchConditions](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-matchconditions) feature.

By combining the policy groups with `matchConditions`, it could be possible to create complex policies that are evaluated only for specific requests.
For instance, it could be possible to build a policy that is evaluated only for requests that match a specific label selector.

This RFC does not include any modifications to the policy CRDs to accommodate `matchConditions`, as it falls outside the scope of this proposal.

## Policy server

The `policies.yaml` settings file will be extended to include policy groups alongside ordinary policies.

```yaml
psp-apparmor:
  url: registry://ghcr.io/kubewarden/policies/psp-apparmor:v0.1.7

psp-capabilities:
  url: registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.7
  allowedToMutate: true
  settings:
    allowed_capabilities: ["*"]
    required_drop_capabilities: ["KILL"]

pod-image-signatures: # policy group
  policies:
    - name: sigstore_pgp
      module: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.8
      settings:
        signatures:
          - image: "*"
            pubKeys:
              - "-----BEGIN PUBLIC KEY-----xxxxx-----END PUBLIC KEY-----"
              - "-----BEGIN PUBLIC KEY-----xxxxx-----END PUBLIC KEY-----"
    - name: sigstore_gh_action
      module: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.8
      settings:
        signatures:
          - image: "*"
            githubActions:
            owner: "kubewarden"
    - name: reject_latest_tag
      module: ghcr.io/kubewarden/policies/trusted-repos-policy:v0.1.12
      settings:
        tags:
          reject:
            - latest
  expression: "sigstore_pgp() || (sigstore_gh_action() && reject_latest_tag())"
  message: "The group policy is rejected."
```

### Expression evaluation

Unfortunately, no production-ready CEL library is available for Rust.
To emulate the behavior and the syntax of CEL, we will use [Rhai](https://rhai.rs/), a small, fast, easy-to-use scripting language and evaluation engine that integrates tightly with Rust.

Rhai has the following features that make it a good candidate for this task:

- function calls have the same syntax as CEL
- it is easy to embed in a Rust application
- it provides a way to create a [minimal engine](https://rhai.rs/book/engine/raw.html) with a bare minimum set of functionalities
- it does not add a considerable overhead (see [Preliminary benchmark](#preliminary-benchmark))
- the language supports [syntax customization](https://rhai.rs/book/engine/custom-syntax.html) if needed

Considering the following expression from the example above:

```rust
sigstore_pgp() || (sigstore_gh_action() && reject_latest_tag())
```

Each policy in the group will be represented as a function call in the expression with the same name as the policy defined in the group.

The expression will be evaluated as follows:

- the `sigstore_pgp` function will be called
- if the result is `true`, the expression will be evaluated as `true`
- if the result is `false`, the `sigstore_gh_action` function will be called
- if the result is `true`, the `latest_tag` function will be called
- if the result is `true`, the expression will be evaluated as `true`

Note that the `sigstore_gh_action` function will be called only if the `sigstore_pgp` function returns `false`.
Similarly, the `reject_latest_tag` function will be called only if the `sigstore_gh_action` function returns `true`.

This avoids evaluating all the policies in the group when the result is already known.

### Settings validation

When the policy server starts, it will validate the settings of the policy groups as well as the ordinary policies.
However, the policy groups will have an additional validation step to ensure that the expression is valid and evaluates to a boolean value.

### Handler

The handler will respond to the `/validate/<group name>` endpoint.
There is no need to create a new endpoint for the group policies, and as far as the API is concerned, the policy groups will be treated as ordinary policies.

After the validation step, precompiled policies and group settings will be added to the `EvaluationEnvironment`.
When a validation request is received, if the policy is a group policy, the `EvaluationEnvironment` performs the following steps:

- create a new Rhai [raw Engine](https://rhai.rs/book/engine/raw.html?highlight=raw%20eng#raw-engine)
- bind native functions to the engine that validate the policy
- call the engine eval method with the expression
- return the result

Creating a new engine for each request is desirable because it avoids contention and locking of the Engine instance.
This pattern is described in the Rhai book, under the [One Engine Instance Per Call](https://rhai.rs/book/patterns/parallel.html?highlight=one%20engine%20per#one-engine-instance-per-call) section.

To improve performance, we could consider precompiling the AST of the expression when building the `EvaluationEnvironment`.
Also, we could consider creating a [custom package](https://rhai.rs/book/rust/packages/create.html?highlight=custom%20package#create-a-custom-package) to instantiate the policy function calls only once.

### Raw policy groups

The policy server will support [raw policy](https://docs.kubewarden.io/tutorials/writing-policies/wasi/raw-policies) groups out of the box since the group evaluation logic is implemented in the `EvaluationEnvironment`.
It will be possible to define a policy group with raw policies only and evaluate the expression by calling the `validate_raw/<group name>` endpoint.

## Scaffolding

The `kwctl` tool will be extended to support the scaffolding of policy groups.
Running a policy or a policy group directly from a CRD definition through `kwctl` is a common use case,
but the implementation of this feature falls outside the scope of this RFC.

## Preliminary benchmark

The following results are based on the [Kubewarden k6 load test](https://github.com/kubewarden/load-testing/tree/k6) using the [psp-apparmor policy](https://github.com/kubewarden/apparmor-psp-policy)

|               |                          | http_req_duration |
| ------------- | ------------------------ | ----------------- |
| single policy | psp-apparmor             | avg=2.02ms        |
| group policy  | `psp-apparmor() && true` | avg=2.46ms        |

Note that no optimizations were made to the Rhai engine in this POC implementation.

# Drawbacks

[drawbacks]: #drawbacks

- The implementation of the policy groups will add complexity to the Kubewarden controller and the policy server.
- The expression language used to evaluate the policy groups may not be familiar to all users.
- In the worst case, the policy group evaluation time could be the sum of the evaluation time of all the policies in the group.
  This is even worse if the policy group contains context-aware policies that introduce additional overhead.

# Alternatives

[alternatives]: #alternatives

An alternative to the policy groups could be to create a tool that takes several policies and merges them into a new WASN module.
The new WASM module would embed the original ones and would have a `main` function that takes care of evaluating the expression given by the user.

This approach has the following drawbacks:

- The complexity of implementing this solution
- The user would require an extra compilation step to create the new WASM module
- The size of the new WASM module would be significantly larger if several policies were embedded
- At runtime, the de-duplication optimization of the policies would be lost, increasing the memory footprint

# Unresolved questions

[unresolved]: #unresolved-questions

- Unfortunately, no production-ready CEL library is available for Rust.
  Some experiments were made with [cel-rust](https://github.com/clarkmcc/cel-rust) and [rscel](https://github.com/1BADragon/rscel)
  but they do not pass the official compliance tests yet and are not actively developed.

- Furthermore, using two different expression languages in the Kubewarden controller and the policy server could lead to inconsistencies in the validation step.
  For instance, it is possible that an expression that is valid in the Kubewarden controller is not valid in the policy server.
  With the current proposal, this expression `"foo".startsWith("f") && policy_1() || policy_2()` would be valid in the Kubewarden controller but not in the policy server,
  since Rhai can be customized to strip down types, standard library functions, and operators that are not needed, keeping only the policy functions and the logical operators.
  However, [this issue](https://github.com/google/cel-go/issues/899) hints that CEL could be stripped down to a minimal set of functionalities as well.

- Running a policy group locally for development or testing purposes should be possible with the `kwctl` tool.
  However, implementing this feature means that the `kwctl` tool should be able to run a policy group directly from a CRD definition.
  As this feature also applies to ordinary policies, it falls outside the scope of this RFC.
