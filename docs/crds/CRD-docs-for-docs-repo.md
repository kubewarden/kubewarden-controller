# API Reference

## Packages
- [policies.kubewarden.io/v1](#policieskubewardeniov1)
- [policies.kubewarden.io/v1alpha2](#policieskubewardeniov1alpha2)


## policies.kubewarden.io/v1

Package v1 contains API Schema definitions for the policies v1 API group

### Resource Types
- [AdmissionPolicy](#admissionpolicy)
- [AdmissionPolicyList](#admissionpolicylist)
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)
- [PolicyServer](#policyserver)
- [PolicyServerList](#policyserverlist)



#### AdmissionPolicy



AdmissionPolicy is the Schema for the admissionpolicies API

_Appears in:_
- [AdmissionPolicyList](#admissionpolicylist)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1`
| `kind` _string_ | `AdmissionPolicy`
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `spec` _[AdmissionPolicySpec](#admissionpolicyspec)_ |  |


#### AdmissionPolicyList



AdmissionPolicyList contains a list of AdmissionPolicy



| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1`
| `kind` _string_ | `AdmissionPolicyList`
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `items` _[AdmissionPolicy](#admissionpolicy) array_ |  |


#### AdmissionPolicySpec



AdmissionPolicySpec defines the desired state of AdmissionPolicy

_Appears in:_
- [AdmissionPolicy](#admissionpolicy)

| Field | Description |
| --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). If prefix is missing, it will default to registry:// and use that internally. |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead. |
| `settings` _[RawExtension](#rawextension)_ | Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule. |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail" |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate incoming requests or not. |
| `backgroundAudit` _boolean_ | BackgroundAudit indicates whether a policy should be used or skipped when performing audit checks. If false, the policy cannot produce meaningful evaluation results during audit checks and will be skipped. The default is "true". |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". <ul> <li> Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. </li> <li> Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. </li> </ul> Defaults to "Equivalent" |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything. |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some. |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds. |


#### ClusterAdmissionPolicy



ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API

_Appears in:_
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1`
| `kind` _string_ | `ClusterAdmissionPolicy`
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `spec` _[ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)_ |  |


#### ClusterAdmissionPolicyList



ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy



| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1`
| `kind` _string_ | `ClusterAdmissionPolicyList`
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `items` _[ClusterAdmissionPolicy](#clusteradmissionpolicy) array_ |  |


#### ClusterAdmissionPolicySpec



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy

_Appears in:_
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

| Field | Description |
| --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). If prefix is missing, it will default to registry:// and use that internally. |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead. |
| `settings` _[RawExtension](#rawextension)_ | Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule. |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail" |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate incoming requests or not. |
| `backgroundAudit` _boolean_ | BackgroundAudit indicates whether a policy should be used or skipped when performing audit checks. If false, the policy cannot produce meaningful evaluation results during audit checks and will be skipped. The default is "true". |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". <ul> <li> Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. </li> <li> Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. </li> </ul> Defaults to "Equivalent" |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything. |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some. |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds. |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | NamespaceSelector decides whether to run the webhook on an object based on whether the namespace for that object matches the selector. If the object itself is a namespace, the matching is performed on object.metadata.labels. If the object is another cluster scoped resource, it never skips the webhook. <br/><br/> For example, to run the webhook on any objects whose namespace is not associated with "runlevel" of "0" or "1";  you will set the selector as follows: <pre> "namespaceSelector": \{<br/> &nbsp;&nbsp;"matchExpressions": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;\{<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "runlevel",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "NotIn",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"0",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"1"<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/> &nbsp;&nbsp;&nbsp;&nbsp;\}<br/> &nbsp;&nbsp;]<br/> \} </pre> If instead you want to only run the webhook on any objects whose namespace is associated with the "environment" of "prod" or "staging"; you will set the selector as follows: <pre> "namespaceSelector": \{<br/> &nbsp;&nbsp;"matchExpressions": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;\{<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "environment",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "In",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"prod",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"staging"<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/> &nbsp;&nbsp;&nbsp;&nbsp;\}<br/> &nbsp;&nbsp;]<br/> \} </pre> See https://kubernetes.io/docs/concepts/overview/working-with-objects/labels for more examples of label selectors. <br/><br/> Default to the empty LabelSelector, which matches everything. |
| `contextAwareResources` _[ContextAwareResource](#contextawareresource) array_ | List of Kubernetes resources the policy is allowed to access at evaluation time. Access to these resources is done using the `ServiceAccount` of the PolicyServer the policy is assigned to. |


#### ContextAwareResource



ContextAwareResource identifies a Kubernetes resource

_Appears in:_
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | apiVersion of the resource (v1 for core group, groupName/groupVersions for other). |
| `kind` _string_ | Singular PascalCase name of the resource |




#### PolicyMode

_Underlying type:_ `string`



_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)
- [PolicySpec](#policyspec)



#### PolicyModeStatus

_Underlying type:_ `string`



_Appears in:_
- [PolicyStatus](#policystatus)



#### PolicyServer



PolicyServer is the Schema for the policyservers API

_Appears in:_
- [PolicyServerList](#policyserverlist)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1`
| `kind` _string_ | `PolicyServer`
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `spec` _[PolicyServerSpec](#policyserverspec)_ |  |


#### PolicyServerList



PolicyServerList contains a list of PolicyServer



| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1`
| `kind` _string_ | `PolicyServerList`
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `items` _[PolicyServer](#policyserver) array_ |  |


#### PolicyServerSecurity



PolicyServerSecurity defines securityContext configuration to be used in the Policy Server workload

_Appears in:_
- [PolicyServerSpec](#policyserverspec)

| Field | Description |
| --- | --- |
| `container` _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#securitycontext-v1-core)_ | securityContext definition to be used in the policy server container |
| `pod` _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#podsecuritycontext-v1-core)_ | podSecurityContext definition to be used in the policy server Pod |


#### PolicyServerSpec



PolicyServerSpec defines the desired state of PolicyServer

_Appears in:_
- [PolicyServer](#policyserver)

| Field | Description |
| --- | --- |
| `image` _string_ | Docker image name. |
| `replicas` _integer_ | Replicas is the number of desired replicas. |
| `annotations` _object (keys:string, values:string)_ | Annotations is an unstructured key value map stored with a resource that may be set by external tools to store and retrieve arbitrary metadata. They are not queryable and should be preserved when modifying objects. More info: http://kubernetes.io/docs/user-guide/annotations |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#envvar-v1-core) array_ | List of environment variables to set in the container. |
| `serviceAccountName` _string_ | Name of the service account associated with the policy server. Namespace service account will be used if not specified. |
| `imagePullSecret` _string_ | Name of ImagePullSecret secret in the same namespace, used for pulling policies from repositories. |
| `insecureSources` _string array_ | List of insecure URIs to policy repositories. |
| `sourceAuthorities` _object (keys:string, values:string array)_ | Key value map of registry URIs endpoints to a list of their associated PEM encoded certificate authorities that have to be used to verify the certificate used by the endpoint. |
| `verificationConfig` _string_ | Name of VerificationConfig configmap in the same namespace, containing Sigstore verification configuration. The configuration must be under a key named verification-config in the Configmap. |
| `securityContexts` _[PolicyServerSecurity](#policyserversecurity)_ | Security configuration to be used in the Policy Server workload. The field allows different configurations for the pod and containers. This configuration will not be used in containers added by other controllers (e.g. telemetry sidecars) |




#### PolicySpec





_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

| Field | Description |
| --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). If prefix is missing, it will default to registry:// and use that internally. |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead. |
| `settings` _[RawExtension](#rawextension)_ | Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule. |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail" |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate incoming requests or not. |
| `backgroundAudit` _boolean_ | BackgroundAudit indicates whether a policy should be used or skipped when performing audit checks. If false, the policy cannot produce meaningful evaluation results during audit checks and will be skipped. The default is "true". |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". <ul> <li> Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. </li> <li> Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. </li> </ul> Defaults to "Equivalent" |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything. |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some. |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds. |




#### PolicyStatusEnum

_Underlying type:_ `string`



_Appears in:_
- [PolicyStatus](#policystatus)




## policies.kubewarden.io/v1alpha2

Package v1alpha2 contains API Schema definitions for the policies v1alpha2 API group

### Resource Types
- [AdmissionPolicy](#admissionpolicy)
- [AdmissionPolicyList](#admissionpolicylist)
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)
- [PolicyServer](#policyserver)
- [PolicyServerList](#policyserverlist)



#### AdmissionPolicy



AdmissionPolicy is the Schema for the admissionpolicies API

_Appears in:_
- [AdmissionPolicyList](#admissionpolicylist)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2`
| `kind` _string_ | `AdmissionPolicy`
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `spec` _[AdmissionPolicySpec](#admissionpolicyspec)_ |  |


#### AdmissionPolicyList



AdmissionPolicyList contains a list of AdmissionPolicy



| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2`
| `kind` _string_ | `AdmissionPolicyList`
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `items` _[AdmissionPolicy](#admissionpolicy) array_ |  |


#### AdmissionPolicySpec



AdmissionPolicySpec defines the desired state of AdmissionPolicy

_Appears in:_
- [AdmissionPolicy](#admissionpolicy)

| Field | Description |
| --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead. |
| `settings` _[RawExtension](#rawextension)_ | Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule. |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail" |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate incoming requests or not. |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". <ul> <li> Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. </li> <li> Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. </li> </ul> Defaults to "Equivalent" |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything. |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some. |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds. |


#### ClusterAdmissionPolicy



ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API

_Appears in:_
- [ClusterAdmissionPolicyList](#clusteradmissionpolicylist)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2`
| `kind` _string_ | `ClusterAdmissionPolicy`
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `spec` _[ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)_ |  |


#### ClusterAdmissionPolicyList



ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy



| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2`
| `kind` _string_ | `ClusterAdmissionPolicyList`
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `items` _[ClusterAdmissionPolicy](#clusteradmissionpolicy) array_ |  |


#### ClusterAdmissionPolicySpec



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy

_Appears in:_
- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

| Field | Description |
| --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead. |
| `settings` _[RawExtension](#rawextension)_ | Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule. |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail" |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate incoming requests or not. |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". <ul> <li> Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. </li> <li> Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. </li> </ul> Defaults to "Equivalent" |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything. |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some. |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds. |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | NamespaceSelector decides whether to run the webhook on an object based on whether the namespace for that object matches the selector. If the object itself is a namespace, the matching is performed on object.metadata.labels. If the object is another cluster scoped resource, it never skips the webhook. <br/><br/> For example, to run the webhook on any objects whose namespace is not associated with "runlevel" of "0" or "1";  you will set the selector as follows: <pre> "namespaceSelector": \{<br/> &nbsp;&nbsp;"matchExpressions": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;\{<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "runlevel",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "NotIn",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"0",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"1"<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/> &nbsp;&nbsp;&nbsp;&nbsp;\}<br/> &nbsp;&nbsp;]<br/> \} </pre> If instead you want to only run the webhook on any objects whose namespace is associated with the "environment" of "prod" or "staging"; you will set the selector as follows: <pre> "namespaceSelector": \{<br/> &nbsp;&nbsp;"matchExpressions": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;\{<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"key": "environment",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"operator": "In",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"values": [<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"prod",<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"staging"<br/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;]<br/> &nbsp;&nbsp;&nbsp;&nbsp;\}<br/> &nbsp;&nbsp;]<br/> \} </pre> See https://kubernetes.io/docs/concepts/overview/working-with-objects/labels for more examples of label selectors. <br/><br/> Default to the empty LabelSelector, which matches everything. |




#### PolicyMode

_Underlying type:_ `string`



_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)
- [PolicySpec](#policyspec)



#### PolicyModeStatus

_Underlying type:_ `string`



_Appears in:_
- [PolicyStatus](#policystatus)



#### PolicyServer



PolicyServer is the Schema for the policyservers API

_Appears in:_
- [PolicyServerList](#policyserverlist)

| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2`
| `kind` _string_ | `PolicyServer`
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `spec` _[PolicyServerSpec](#policyserverspec)_ |  |


#### PolicyServerList



PolicyServerList contains a list of PolicyServer



| Field | Description |
| --- | --- |
| `apiVersion` _string_ | `policies.kubewarden.io/v1alpha2`
| `kind` _string_ | `PolicyServerList`
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |
| `items` _[PolicyServer](#policyserver) array_ |  |


#### PolicyServerSpec



PolicyServerSpec defines the desired state of PolicyServer

_Appears in:_
- [PolicyServer](#policyserver)

| Field | Description |
| --- | --- |
| `image` _string_ | Docker image name. |
| `replicas` _integer_ | Replicas is the number of desired replicas. |
| `annotations` _object (keys:string, values:string)_ | Annotations is an unstructured key value map stored with a resource that may be set by external tools to store and retrieve arbitrary metadata. They are not queryable and should be preserved when modifying objects. More info: http://kubernetes.io/docs/user-guide/annotations |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#envvar-v1-core) array_ | List of environment variables to set in the container. |
| `serviceAccountName` _string_ | Name of the service account associated with the policy server. Namespace service account will be used if not specified. |
| `imagePullSecret` _string_ | Name of ImagePullSecret secret in the same namespace, used for pulling policies from repositories. |
| `insecureSources` _string array_ | List of insecure URIs to policy repositories. |
| `sourceAuthorities` _object (keys:string, values:string array)_ | Key value map of registry URIs endpoints to a list of their associated PEM encoded certificate authorities that have to be used to verify the certificate used by the endpoint. |
| `verificationConfig` _string_ | Name of VerificationConfig configmap in the same namespace, containing Sigstore verification configuration. The configuration must be under a key named verification-config in the Configmap. |




#### PolicySpec





_Appears in:_
- [AdmissionPolicySpec](#admissionpolicyspec)
- [ClusterAdmissionPolicySpec](#clusteradmissionpolicyspec)

| Field | Description |
| --- | --- |
| `policyServer` _string_ | PolicyServer identifies an existing PolicyServer resource. |
| `module` _string_ | Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). |
| `mode` _[PolicyMode](#policymode)_ | Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead. |
| `settings` _[RawExtension](#rawextension)_ | Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false |
| `rules` _[RuleWithOperations](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#rulewithoperations-v1-admissionregistration) array_ | Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule. |
| `failurePolicy` _[FailurePolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#failurepolicytype-v1-admissionregistration)_ | FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail" |
| `mutating` _boolean_ | Mutating indicates whether a policy has the ability to mutate incoming requests or not. |
| `matchPolicy` _[MatchPolicyType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#matchpolicytype-v1-admissionregistration)_ | matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". <ul> <li> Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. </li> <li> Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. </li> </ul> Defaults to "Equivalent" |
| `objectSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta)_ | ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything. |
| `sideEffects` _[SideEffectClass](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#sideeffectclass-v1-admissionregistration)_ | SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some. |
| `timeoutSeconds` _integer_ | TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds. |




#### PolicyStatusEnum

_Underlying type:_ `string`



_Appears in:_
- [PolicyStatus](#policystatus)



