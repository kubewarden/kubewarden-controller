# API Reference

Packages:

- [policies.kubewarden.io/v1](#policieskubewardeniov1)
- [policies.kubewarden.io/v1alpha2](#policieskubewardeniov1alpha2)

# policies.kubewarden.io/v1

Resource Types:

- [AdmissionPolicy](#admissionpolicy)

- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

- [PolicyServer](#policyserver)




## AdmissionPolicy
<sup><sup>[↩ Parent](#policieskubewardeniov1 )</sup></sup>






AdmissionPolicy is the Schema for the admissionpolicies API

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>policies.kubewarden.io/v1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>AdmissionPolicy</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#admissionpolicyspec">spec</a></b></td>
        <td>object</td>
        <td>
          AdmissionPolicySpec defines the desired state of AdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#admissionpolicystatus">status</a></b></td>
        <td>object</td>
        <td>
          PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec
<sup><sup>[↩ Parent](#admissionpolicy)</sup></sup>



AdmissionPolicySpec defines the desired state of AdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>module</b></td>
        <td>string</td>
        <td>
          Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). If prefix is missing, it will default to registry:// and use that internally.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>mutating</b></td>
        <td>boolean</td>
        <td>
          Mutating indicates whether a policy has the ability to mutate incoming requests or not.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#admissionpolicyspecrulesindex">rules</a></b></td>
        <td>[]object</td>
        <td>
          Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>failurePolicy</b></td>
        <td>string</td>
        <td>
          FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchPolicy</b></td>
        <td>string</td>
        <td>
          matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". 
 - Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. 
 - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. 
 Defaults to "Equivalent"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead.<br/>
          <br/>
            <i>Enum</i>: protect, monitor<br/>
            <i>Default</i>: protect<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#admissionpolicyspecobjectselector">objectSelector</a></b></td>
        <td>object</td>
        <td>
          ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>policyServer</b></td>
        <td>string</td>
        <td>
          PolicyServer identifies an existing PolicyServer resource.<br/>
          <br/>
            <i>Default</i>: default<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>settings</b></td>
        <td>object</td>
        <td>
          Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sideEffects</b></td>
        <td>string</td>
        <td>
          SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeoutSeconds</b></td>
        <td>integer</td>
        <td>
          TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 10<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec.rules[index]
<sup><sup>[↩ Parent](#admissionpolicyspec)</sup></sup>



RuleWithOperations is a tuple of Operations and Resources. It is recommended to make sure that all the tuple expansions are valid.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>apiGroups</b></td>
        <td>[]string</td>
        <td>
          APIGroups is the API groups the resources belong to. '*' is all groups. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>apiVersions</b></td>
        <td>[]string</td>
        <td>
          APIVersions is the API versions the resources belong to. '*' is all versions. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>operations</b></td>
        <td>[]string</td>
        <td>
          Operations is the operations the admission hook cares about - CREATE, UPDATE, DELETE, CONNECT or * for all of those operations and any future admission operations that are added. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resources</b></td>
        <td>[]string</td>
        <td>
          Resources is a list of resources this rule applies to. 
 For example: 'pods' means pods. 'pods/log' means the log subresource of pods. '*' means all resources, but not subresources. 'pods/*' means all subresources of pods. '*/scale' means all scale subresources. '*/*' means all resources and their subresources. 
 If wildcard is present, the validation rule will ensure resources do not overlap with each other. 
 Depending on the enclosing object, subresources might not be allowed. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>scope</b></td>
        <td>string</td>
        <td>
          scope specifies the scope of this rule. Valid values are "Cluster", "Namespaced", and "*" "Cluster" means that only cluster-scoped resources will match this rule. Namespace API objects are cluster-scoped. "Namespaced" means that only namespaced resources will match this rule. "*" means that there are no scope restrictions. Subresources match the scope of their parent resource. Default is "*".<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec.objectSelector
<sup><sup>[↩ Parent](#admissionpolicyspec)</sup></sup>



ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#admissionpolicyspecobjectselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec.objectSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#admissionpolicyspecobjectselector)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.status
<sup><sup>[↩ Parent](#admissionpolicy)</sup></sup>



PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>policyStatus</b></td>
        <td>enum</td>
        <td>
          PolicyStatus represents the observed status of the policy<br/>
          <br/>
            <i>Enum</i>: unscheduled, scheduled, pending, active<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#admissionpolicystatusconditionsindex">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the observed conditions of the ClusterAdmissionPolicy resource.  Known .status.conditions.types are: "PolicyServerSecretReconciled", "PolicyServerConfigMapReconciled", "PolicyServerDeploymentReconciled", "PolicyServerServiceReconciled" and "AdmissionPolicyActive"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          PolicyMode represents the observed policy mode of this policy in the associated PolicyServer configuration<br/>
          <br/>
            <i>Enum</i>: protect, monitor, unknown<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.status.conditions[index]
<sup><sup>[↩ Parent](#admissionpolicystatus)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
 type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
 // other fields }

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition. This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>

## ClusterAdmissionPolicy
<sup><sup>[↩ Parent](#policieskubewardeniov1 )</sup></sup>






ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>policies.kubewarden.io/v1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>ClusterAdmissionPolicy</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspec">spec</a></b></td>
        <td>object</td>
        <td>
          ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicystatus">status</a></b></td>
        <td>object</td>
        <td>
          PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec
<sup><sup>[↩ Parent](#clusteradmissionpolicy)</sup></sup>



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>module</b></td>
        <td>string</td>
        <td>
          Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://). If prefix is missing, it will default to registry:// and use that internally.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>mutating</b></td>
        <td>boolean</td>
        <td>
          Mutating indicates whether a policy has the ability to mutate incoming requests or not.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspecrulesindex">rules</a></b></td>
        <td>[]object</td>
        <td>
          Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>failurePolicy</b></td>
        <td>string</td>
        <td>
          FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchPolicy</b></td>
        <td>string</td>
        <td>
          matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". 
 - Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. 
 - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. 
 Defaults to "Equivalent"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead.<br/>
          <br/>
            <i>Enum</i>: protect, monitor<br/>
            <i>Default</i>: protect<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspecnamespaceselector">namespaceSelector</a></b></td>
        <td>object</td>
        <td>
          NamespaceSelector decides whether to run the webhook on an object based on whether the namespace for that object matches the selector. If the object itself is a namespace, the matching is performed on object.metadata.labels. If the object is another cluster scoped resource, it never skips the webhook. 
 For example, to run the webhook on any objects whose namespace is not associated with "runlevel" of "0" or "1";  you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "runlevel", "operator": "NotIn", "values": [ "0", "1" ] } ] } 
 If instead you want to only run the webhook on any objects whose namespace is associated with the "environment" of "prod" or "staging"; you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "environment", "operator": "In", "values": [ "prod", "staging" ] } ] } 
 See https://kubernetes.io/docs/concepts/overview/working-with-objects/labels for more examples of label selectors. 
 Default to the empty LabelSelector, which matches everything.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspecobjectselector">objectSelector</a></b></td>
        <td>object</td>
        <td>
          ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>policyServer</b></td>
        <td>string</td>
        <td>
          PolicyServer identifies an existing PolicyServer resource.<br/>
          <br/>
            <i>Default</i>: default<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>settings</b></td>
        <td>object</td>
        <td>
          Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sideEffects</b></td>
        <td>string</td>
        <td>
          SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeoutSeconds</b></td>
        <td>integer</td>
        <td>
          TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 10<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.rules[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicyspec)</sup></sup>



RuleWithOperations is a tuple of Operations and Resources. It is recommended to make sure that all the tuple expansions are valid.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>apiGroups</b></td>
        <td>[]string</td>
        <td>
          APIGroups is the API groups the resources belong to. '*' is all groups. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>apiVersions</b></td>
        <td>[]string</td>
        <td>
          APIVersions is the API versions the resources belong to. '*' is all versions. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>operations</b></td>
        <td>[]string</td>
        <td>
          Operations is the operations the admission hook cares about - CREATE, UPDATE, DELETE, CONNECT or * for all of those operations and any future admission operations that are added. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resources</b></td>
        <td>[]string</td>
        <td>
          Resources is a list of resources this rule applies to. 
 For example: 'pods' means pods. 'pods/log' means the log subresource of pods. '*' means all resources, but not subresources. 'pods/*' means all subresources of pods. '*/scale' means all scale subresources. '*/*' means all resources and their subresources. 
 If wildcard is present, the validation rule will ensure resources do not overlap with each other. 
 Depending on the enclosing object, subresources might not be allowed. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>scope</b></td>
        <td>string</td>
        <td>
          scope specifies the scope of this rule. Valid values are "Cluster", "Namespaced", and "*" "Cluster" means that only cluster-scoped resources will match this rule. Namespace API objects are cluster-scoped. "Namespaced" means that only namespaced resources will match this rule. "*" means that there are no scope restrictions. Subresources match the scope of their parent resource. Default is "*".<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.namespaceSelector
<sup><sup>[↩ Parent](#clusteradmissionpolicyspec)</sup></sup>



NamespaceSelector decides whether to run the webhook on an object based on whether the namespace for that object matches the selector. If the object itself is a namespace, the matching is performed on object.metadata.labels. If the object is another cluster scoped resource, it never skips the webhook. 
 For example, to run the webhook on any objects whose namespace is not associated with "runlevel" of "0" or "1";  you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "runlevel", "operator": "NotIn", "values": [ "0", "1" ] } ] } 
 If instead you want to only run the webhook on any objects whose namespace is associated with the "environment" of "prod" or "staging"; you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "environment", "operator": "In", "values": [ "prod", "staging" ] } ] } 
 See https://kubernetes.io/docs/concepts/overview/working-with-objects/labels for more examples of label selectors. 
 Default to the empty LabelSelector, which matches everything.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#clusteradmissionpolicyspecnamespaceselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.namespaceSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicyspecnamespaceselector)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.objectSelector
<sup><sup>[↩ Parent](#clusteradmissionpolicyspec)</sup></sup>



ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#clusteradmissionpolicyspecobjectselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.objectSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicyspecobjectselector)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.status
<sup><sup>[↩ Parent](#clusteradmissionpolicy)</sup></sup>



PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>policyStatus</b></td>
        <td>enum</td>
        <td>
          PolicyStatus represents the observed status of the policy<br/>
          <br/>
            <i>Enum</i>: unscheduled, scheduled, pending, active<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicystatusconditionsindex">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the observed conditions of the ClusterAdmissionPolicy resource.  Known .status.conditions.types are: "PolicyServerSecretReconciled", "PolicyServerConfigMapReconciled", "PolicyServerDeploymentReconciled", "PolicyServerServiceReconciled" and "AdmissionPolicyActive"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          PolicyMode represents the observed policy mode of this policy in the associated PolicyServer configuration<br/>
          <br/>
            <i>Enum</i>: protect, monitor, unknown<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.status.conditions[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicystatus)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
 type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
 // other fields }

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition. This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>

## PolicyServer
<sup><sup>[↩ Parent](#policieskubewardeniov1 )</sup></sup>






PolicyServer is the Schema for the policyservers API

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>policies.kubewarden.io/v1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>PolicyServer</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#policyserverspec">spec</a></b></td>
        <td>object</td>
        <td>
          PolicyServerSpec defines the desired state of PolicyServer<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverstatus">status</a></b></td>
        <td>object</td>
        <td>
          PolicyServerStatus defines the observed state of PolicyServer<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec
<sup><sup>[↩ Parent](#policyserver)</sup></sup>



PolicyServerSpec defines the desired state of PolicyServer

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>image</b></td>
        <td>string</td>
        <td>
          Docker image name.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>replicas</b></td>
        <td>integer</td>
        <td>
          Replicas is the number of desired replicas.<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>annotations</b></td>
        <td>map[string]string</td>
        <td>
          Annotations is an unstructured key value map stored with a resource that may be set by external tools to store and retrieve arbitrary metadata. They are not queryable and should be preserved when modifying objects. More info: http://kubernetes.io/docs/user-guide/annotations<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindex">env</a></b></td>
        <td>[]object</td>
        <td>
          List of environment variables to set in the container.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imagePullSecret</b></td>
        <td>string</td>
        <td>
          Name of ImagePullSecret secret in the same namespace, used for pulling policies from repositories.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>insecureSources</b></td>
        <td>[]string</td>
        <td>
          List of insecure URIs to policy repositories.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>serviceAccountName</b></td>
        <td>string</td>
        <td>
          Name of the service account associated with the policy server. Namespace service account will be used if not specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sourceAuthorities</b></td>
        <td>map[string][]string</td>
        <td>
          Key value map of registry URIs endpoints to a list of their associated PEM encoded certificate authorities that have to be used to verify the certificate used by the endpoint.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>verificationConfig</b></td>
        <td>string</td>
        <td>
          Name of VerificationConfig configmap in the same namespace, containing Sigstore verification configuration. The configuration must be under a key named verification-config in the Configmap.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index]
<sup><sup>[↩ Parent](#policyserverspec)</sup></sup>



EnvVar represents an environment variable present in a Container.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the environment variable. Must be a C_IDENTIFIER.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>value</b></td>
        <td>string</td>
        <td>
          Variable references $(VAR_NAME) are expanded using the previously defined environment variables in the container and any service environment variables. If a variable cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless of whether the variable exists or not. Defaults to "".<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefrom">valueFrom</a></b></td>
        <td>object</td>
        <td>
          Source for the environment variable's value. Cannot be used if value is not empty.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom
<sup><sup>[↩ Parent](#policyserverspecenvindex)</sup></sup>



Source for the environment variable's value. Cannot be used if value is not empty.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromconfigmapkeyref">configMapKeyRef</a></b></td>
        <td>object</td>
        <td>
          Selects a key of a ConfigMap.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromfieldref">fieldRef</a></b></td>
        <td>object</td>
        <td>
          Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromresourcefieldref">resourceFieldRef</a></b></td>
        <td>object</td>
        <td>
          Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromsecretkeyref">secretKeyRef</a></b></td>
        <td>object</td>
        <td>
          Selects a key of a secret in the pod's namespace<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.configMapKeyRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom)</sup></sup>



Selects a key of a ConfigMap.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          The key to select.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>optional</b></td>
        <td>boolean</td>
        <td>
          Specify whether the ConfigMap or its key must be defined<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.fieldRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom)</sup></sup>



Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>fieldPath</b></td>
        <td>string</td>
        <td>
          Path of the field to select in the specified API version.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>apiVersion</b></td>
        <td>string</td>
        <td>
          Version of the schema the FieldPath is written in terms of, defaults to "v1".<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.resourceFieldRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom)</sup></sup>



Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>resource</b></td>
        <td>string</td>
        <td>
          Required: resource to select<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>containerName</b></td>
        <td>string</td>
        <td>
          Container name: required for volumes, optional for env vars<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>divisor</b></td>
        <td>int or string</td>
        <td>
          Specifies the output format of the exposed resources, defaults to "1"<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.secretKeyRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom)</sup></sup>



Selects a key of a secret in the pod's namespace

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          The key of the secret to select from.  Must be a valid secret key.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>optional</b></td>
        <td>boolean</td>
        <td>
          Specify whether the Secret or its key must be defined<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.status
<sup><sup>[↩ Parent](#policyserver)</sup></sup>



PolicyServerStatus defines the observed state of PolicyServer

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#policyserverstatusconditionsindex">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the observed conditions of the PolicyServer resource.  Known .status.conditions.types are: "PolicyServerSecretReconciled", "PolicyServerDeploymentReconciled" and "PolicyServerServiceReconciled"<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### PolicyServer.status.conditions[index]
<sup><sup>[↩ Parent](#policyserverstatus)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
 type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
 // other fields }

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition. This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>

# policies.kubewarden.io/v1alpha2

Resource Types:

- [AdmissionPolicy](#admissionpolicy)

- [ClusterAdmissionPolicy](#clusteradmissionpolicy)

- [PolicyServer](#policyserver)




## AdmissionPolicy
<sup><sup>[↩ Parent](#policieskubewardeniov1alpha2 )</sup></sup>






AdmissionPolicy is the Schema for the admissionpolicies API

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>policies.kubewarden.io/v1alpha2</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>AdmissionPolicy</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#admissionpolicyspec-1">spec</a></b></td>
        <td>object</td>
        <td>
          AdmissionPolicySpec defines the desired state of AdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#admissionpolicystatus-1">status</a></b></td>
        <td>object</td>
        <td>
          PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec
<sup><sup>[↩ Parent](#admissionpolicy-1)</sup></sup>



AdmissionPolicySpec defines the desired state of AdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>module</b></td>
        <td>string</td>
        <td>
          Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://).<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>mutating</b></td>
        <td>boolean</td>
        <td>
          Mutating indicates whether a policy has the ability to mutate incoming requests or not.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#admissionpolicyspecrulesindex-1">rules</a></b></td>
        <td>[]object</td>
        <td>
          Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>failurePolicy</b></td>
        <td>string</td>
        <td>
          FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchPolicy</b></td>
        <td>string</td>
        <td>
          matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". 
 - Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. 
 - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. 
 Defaults to "Equivalent"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead.<br/>
          <br/>
            <i>Enum</i>: protect, monitor<br/>
            <i>Default</i>: protect<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#admissionpolicyspecobjectselector-1">objectSelector</a></b></td>
        <td>object</td>
        <td>
          ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>policyServer</b></td>
        <td>string</td>
        <td>
          PolicyServer identifies an existing PolicyServer resource.<br/>
          <br/>
            <i>Default</i>: default<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>settings</b></td>
        <td>object</td>
        <td>
          Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sideEffects</b></td>
        <td>string</td>
        <td>
          SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeoutSeconds</b></td>
        <td>integer</td>
        <td>
          TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 10<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec.rules[index]
<sup><sup>[↩ Parent](#admissionpolicyspec-1)</sup></sup>



RuleWithOperations is a tuple of Operations and Resources. It is recommended to make sure that all the tuple expansions are valid.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>apiGroups</b></td>
        <td>[]string</td>
        <td>
          APIGroups is the API groups the resources belong to. '*' is all groups. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>apiVersions</b></td>
        <td>[]string</td>
        <td>
          APIVersions is the API versions the resources belong to. '*' is all versions. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>operations</b></td>
        <td>[]string</td>
        <td>
          Operations is the operations the admission hook cares about - CREATE, UPDATE, DELETE, CONNECT or * for all of those operations and any future admission operations that are added. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resources</b></td>
        <td>[]string</td>
        <td>
          Resources is a list of resources this rule applies to. 
 For example: 'pods' means pods. 'pods/log' means the log subresource of pods. '*' means all resources, but not subresources. 'pods/*' means all subresources of pods. '*/scale' means all scale subresources. '*/*' means all resources and their subresources. 
 If wildcard is present, the validation rule will ensure resources do not overlap with each other. 
 Depending on the enclosing object, subresources might not be allowed. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>scope</b></td>
        <td>string</td>
        <td>
          scope specifies the scope of this rule. Valid values are "Cluster", "Namespaced", and "*" "Cluster" means that only cluster-scoped resources will match this rule. Namespace API objects are cluster-scoped. "Namespaced" means that only namespaced resources will match this rule. "*" means that there are no scope restrictions. Subresources match the scope of their parent resource. Default is "*".<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec.objectSelector
<sup><sup>[↩ Parent](#admissionpolicyspec-1)</sup></sup>



ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#admissionpolicyspecobjectselectormatchexpressionsindex-1">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.spec.objectSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#admissionpolicyspecobjectselector-1)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.status
<sup><sup>[↩ Parent](#admissionpolicy-1)</sup></sup>



PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>policyStatus</b></td>
        <td>enum</td>
        <td>
          PolicyStatus represents the observed status of the policy<br/>
          <br/>
            <i>Enum</i>: unscheduled, scheduled, pending, active<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#admissionpolicystatusconditionsindex-1">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the observed conditions of the ClusterAdmissionPolicy resource.  Known .status.conditions.types are: "PolicyServerSecretReconciled", "PolicyServerConfigMapReconciled", "PolicyServerDeploymentReconciled", "PolicyServerServiceReconciled" and "AdmissionPolicyActive"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          PolicyMode represents the observed policy mode of this policy in the associated PolicyServer configuration<br/>
          <br/>
            <i>Enum</i>: protect, monitor, unknown<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### AdmissionPolicy.status.conditions[index]
<sup><sup>[↩ Parent](#admissionpolicystatus-1)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
 type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
 // other fields }

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition. This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>

## ClusterAdmissionPolicy
<sup><sup>[↩ Parent](#policieskubewardeniov1alpha2 )</sup></sup>






ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>policies.kubewarden.io/v1alpha2</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>ClusterAdmissionPolicy</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspec-1">spec</a></b></td>
        <td>object</td>
        <td>
          ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicystatus-1">status</a></b></td>
        <td>object</td>
        <td>
          PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec
<sup><sup>[↩ Parent](#clusteradmissionpolicy-1)</sup></sup>



ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>module</b></td>
        <td>string</td>
        <td>
          Module is the location of the WASM module to be loaded. Can be a local file (file://), a remote file served by an HTTP server (http://, https://), or an artifact served by an OCI-compatible registry (registry://).<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>mutating</b></td>
        <td>boolean</td>
        <td>
          Mutating indicates whether a policy has the ability to mutate incoming requests or not.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspecrulesindex-1">rules</a></b></td>
        <td>[]object</td>
        <td>
          Rules describes what operations on what resources/subresources the webhook cares about. The webhook cares about an operation if it matches _any_ Rule.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>failurePolicy</b></td>
        <td>string</td>
        <td>
          FailurePolicy defines how unrecognized errors and timeout errors from the policy are handled. Allowed values are "Ignore" or "Fail". * "Ignore" means that an error calling the webhook is ignored and the API request is allowed to continue. * "Fail" means that an error calling the webhook causes the admission to fail and the API request to be rejected. The default behaviour is "Fail"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchPolicy</b></td>
        <td>string</td>
        <td>
          matchPolicy defines how the "rules" list is used to match incoming requests. Allowed values are "Exact" or "Equivalent". 
 - Exact: match a request only if it exactly matches a specified rule. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook. 
 - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version. For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1, and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`, a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook. 
 Defaults to "Equivalent"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          Mode defines the execution mode of this policy. Can be set to either "protect" or "monitor". If it's empty, it is defaulted to "protect". Transitioning this setting from "monitor" to "protect" is allowed, but is disallowed to transition from "protect" to "monitor". To perform this transition, the policy should be recreated in "monitor" mode instead.<br/>
          <br/>
            <i>Enum</i>: protect, monitor<br/>
            <i>Default</i>: protect<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspecnamespaceselector-1">namespaceSelector</a></b></td>
        <td>object</td>
        <td>
          NamespaceSelector decides whether to run the webhook on an object based on whether the namespace for that object matches the selector. If the object itself is a namespace, the matching is performed on object.metadata.labels. If the object is another cluster scoped resource, it never skips the webhook. 
 For example, to run the webhook on any objects whose namespace is not associated with "runlevel" of "0" or "1";  you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "runlevel", "operator": "NotIn", "values": [ "0", "1" ] } ] } 
 If instead you want to only run the webhook on any objects whose namespace is associated with the "environment" of "prod" or "staging"; you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "environment", "operator": "In", "values": [ "prod", "staging" ] } ] } 
 See https://kubernetes.io/docs/concepts/overview/working-with-objects/labels for more examples of label selectors. 
 Default to the empty LabelSelector, which matches everything.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicyspecobjectselector-1">objectSelector</a></b></td>
        <td>object</td>
        <td>
          ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>policyServer</b></td>
        <td>string</td>
        <td>
          PolicyServer identifies an existing PolicyServer resource.<br/>
          <br/>
            <i>Default</i>: default<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>settings</b></td>
        <td>object</td>
        <td>
          Settings is a free-form object that contains the policy configuration values. x-kubernetes-embedded-resource: false<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sideEffects</b></td>
        <td>string</td>
        <td>
          SideEffects states whether this webhook has side effects. Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown). Webhooks with side effects MUST implement a reconciliation system, since a request may be rejected by a future step in the admission change and the side effects therefore need to be undone. Requests with the dryRun attribute will be auto-rejected if they match a webhook with sideEffects == Unknown or Some.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>timeoutSeconds</b></td>
        <td>integer</td>
        <td>
          TimeoutSeconds specifies the timeout for this webhook. After the timeout passes, the webhook call will be ignored or the API call will fail based on the failure policy. The timeout value must be between 1 and 30 seconds. Default to 10 seconds.<br/>
          <br/>
            <i>Format</i>: int32<br/>
            <i>Default</i>: 10<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.rules[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicyspec-1)</sup></sup>



RuleWithOperations is a tuple of Operations and Resources. It is recommended to make sure that all the tuple expansions are valid.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>apiGroups</b></td>
        <td>[]string</td>
        <td>
          APIGroups is the API groups the resources belong to. '*' is all groups. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>apiVersions</b></td>
        <td>[]string</td>
        <td>
          APIVersions is the API versions the resources belong to. '*' is all versions. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>operations</b></td>
        <td>[]string</td>
        <td>
          Operations is the operations the admission hook cares about - CREATE, UPDATE, DELETE, CONNECT or * for all of those operations and any future admission operations that are added. If '*' is present, the length of the slice must be one. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>resources</b></td>
        <td>[]string</td>
        <td>
          Resources is a list of resources this rule applies to. 
 For example: 'pods' means pods. 'pods/log' means the log subresource of pods. '*' means all resources, but not subresources. 'pods/*' means all subresources of pods. '*/scale' means all scale subresources. '*/*' means all resources and their subresources. 
 If wildcard is present, the validation rule will ensure resources do not overlap with each other. 
 Depending on the enclosing object, subresources might not be allowed. Required.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>scope</b></td>
        <td>string</td>
        <td>
          scope specifies the scope of this rule. Valid values are "Cluster", "Namespaced", and "*" "Cluster" means that only cluster-scoped resources will match this rule. Namespace API objects are cluster-scoped. "Namespaced" means that only namespaced resources will match this rule. "*" means that there are no scope restrictions. Subresources match the scope of their parent resource. Default is "*".<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.namespaceSelector
<sup><sup>[↩ Parent](#clusteradmissionpolicyspec-1)</sup></sup>



NamespaceSelector decides whether to run the webhook on an object based on whether the namespace for that object matches the selector. If the object itself is a namespace, the matching is performed on object.metadata.labels. If the object is another cluster scoped resource, it never skips the webhook. 
 For example, to run the webhook on any objects whose namespace is not associated with "runlevel" of "0" or "1";  you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "runlevel", "operator": "NotIn", "values": [ "0", "1" ] } ] } 
 If instead you want to only run the webhook on any objects whose namespace is associated with the "environment" of "prod" or "staging"; you will set the selector as follows: "namespaceSelector": { "matchExpressions": [ { "key": "environment", "operator": "In", "values": [ "prod", "staging" ] } ] } 
 See https://kubernetes.io/docs/concepts/overview/working-with-objects/labels for more examples of label selectors. 
 Default to the empty LabelSelector, which matches everything.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#clusteradmissionpolicyspecnamespaceselectormatchexpressionsindex-1">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.namespaceSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicyspecnamespaceselector-1)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.objectSelector
<sup><sup>[↩ Parent](#clusteradmissionpolicyspec-1)</sup></sup>



ObjectSelector decides whether to run the webhook based on if the object has matching labels. objectSelector is evaluated against both the oldObject and newObject that would be sent to the webhook, and is considered to match if either object matches the selector. A null object (oldObject in the case of create, or newObject in the case of delete) or an object that cannot have labels (like a DeploymentRollback or a PodProxyOptions object) is not considered to match. Use the object selector only if the webhook is opt-in, because end users may skip the admission webhook by setting the labels. Default to the empty LabelSelector, which matches everything.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#clusteradmissionpolicyspecobjectselectormatchexpressionsindex-1">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.spec.objectSelector.matchExpressions[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicyspecobjectselector-1)</sup></sup>



A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.status
<sup><sup>[↩ Parent](#clusteradmissionpolicy-1)</sup></sup>



PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>policyStatus</b></td>
        <td>enum</td>
        <td>
          PolicyStatus represents the observed status of the policy<br/>
          <br/>
            <i>Enum</i>: unscheduled, scheduled, pending, active<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#clusteradmissionpolicystatusconditionsindex-1">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the observed conditions of the ClusterAdmissionPolicy resource.  Known .status.conditions.types are: "PolicyServerSecretReconciled", "PolicyServerConfigMapReconciled", "PolicyServerDeploymentReconciled", "PolicyServerServiceReconciled" and "AdmissionPolicyActive"<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>mode</b></td>
        <td>enum</td>
        <td>
          PolicyMode represents the observed policy mode of this policy in the associated PolicyServer configuration<br/>
          <br/>
            <i>Enum</i>: protect, monitor, unknown<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### ClusterAdmissionPolicy.status.conditions[index]
<sup><sup>[↩ Parent](#clusteradmissionpolicystatus-1)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
 type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
 // other fields }

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition. This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>

## PolicyServer
<sup><sup>[↩ Parent](#policieskubewardeniov1alpha2 )</sup></sup>






PolicyServer is the Schema for the policyservers API

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>policies.kubewarden.io/v1alpha2</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>PolicyServer</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#policyserverspec-1">spec</a></b></td>
        <td>object</td>
        <td>
          PolicyServerSpec defines the desired state of PolicyServer<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverstatus-1">status</a></b></td>
        <td>object</td>
        <td>
          PolicyServerStatus defines the observed state of PolicyServer<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec
<sup><sup>[↩ Parent](#policyserver-1)</sup></sup>



PolicyServerSpec defines the desired state of PolicyServer

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>image</b></td>
        <td>string</td>
        <td>
          Docker image name.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>replicas</b></td>
        <td>integer</td>
        <td>
          Replicas is the number of desired replicas.<br/>
          <br/>
            <i>Format</i>: int32<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>annotations</b></td>
        <td>map[string]string</td>
        <td>
          Annotations is an unstructured key value map stored with a resource that may be set by external tools to store and retrieve arbitrary metadata. They are not queryable and should be preserved when modifying objects. More info: http://kubernetes.io/docs/user-guide/annotations<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindex-1">env</a></b></td>
        <td>[]object</td>
        <td>
          List of environment variables to set in the container.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>imagePullSecret</b></td>
        <td>string</td>
        <td>
          Name of ImagePullSecret secret in the same namespace, used for pulling policies from repositories.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>insecureSources</b></td>
        <td>[]string</td>
        <td>
          List of insecure URIs to policy repositories.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>serviceAccountName</b></td>
        <td>string</td>
        <td>
          Name of the service account associated with the policy server. Namespace service account will be used if not specified.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>sourceAuthorities</b></td>
        <td>map[string][]string</td>
        <td>
          Key value map of registry URIs endpoints to a list of their associated PEM encoded certificate authorities that have to be used to verify the certificate used by the endpoint.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>verificationConfig</b></td>
        <td>string</td>
        <td>
          Name of VerificationConfig configmap in the same namespace, containing Sigstore verification configuration. The configuration must be under a key named verification-config in the Configmap.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index]
<sup><sup>[↩ Parent](#policyserverspec-1)</sup></sup>



EnvVar represents an environment variable present in a Container.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the environment variable. Must be a C_IDENTIFIER.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>value</b></td>
        <td>string</td>
        <td>
          Variable references $(VAR_NAME) are expanded using the previously defined environment variables in the container and any service environment variables. If a variable cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless of whether the variable exists or not. Defaults to "".<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefrom-1">valueFrom</a></b></td>
        <td>object</td>
        <td>
          Source for the environment variable's value. Cannot be used if value is not empty.<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom
<sup><sup>[↩ Parent](#policyserverspecenvindex-1)</sup></sup>



Source for the environment variable's value. Cannot be used if value is not empty.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromconfigmapkeyref-1">configMapKeyRef</a></b></td>
        <td>object</td>
        <td>
          Selects a key of a ConfigMap.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromfieldref-1">fieldRef</a></b></td>
        <td>object</td>
        <td>
          Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromresourcefieldref-1">resourceFieldRef</a></b></td>
        <td>object</td>
        <td>
          Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#policyserverspecenvindexvaluefromsecretkeyref-1">secretKeyRef</a></b></td>
        <td>object</td>
        <td>
          Selects a key of a secret in the pod's namespace<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.configMapKeyRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom-1)</sup></sup>



Selects a key of a ConfigMap.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          The key to select.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>optional</b></td>
        <td>boolean</td>
        <td>
          Specify whether the ConfigMap or its key must be defined<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.fieldRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom-1)</sup></sup>



Selects a field of the pod: supports metadata.name, metadata.namespace, `metadata.labels['<KEY>']`, `metadata.annotations['<KEY>']`, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>fieldPath</b></td>
        <td>string</td>
        <td>
          Path of the field to select in the specified API version.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>apiVersion</b></td>
        <td>string</td>
        <td>
          Version of the schema the FieldPath is written in terms of, defaults to "v1".<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.resourceFieldRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom-1)</sup></sup>



Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>resource</b></td>
        <td>string</td>
        <td>
          Required: resource to select<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>containerName</b></td>
        <td>string</td>
        <td>
          Container name: required for volumes, optional for env vars<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>divisor</b></td>
        <td>int or string</td>
        <td>
          Specifies the output format of the exposed resources, defaults to "1"<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.spec.env[index].valueFrom.secretKeyRef
<sup><sup>[↩ Parent](#policyserverspecenvindexvaluefrom-1)</sup></sup>



Selects a key of a secret in the pod's namespace

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          The key of the secret to select from.  Must be a valid secret key.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>optional</b></td>
        <td>boolean</td>
        <td>
          Specify whether the Secret or its key must be defined<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### PolicyServer.status
<sup><sup>[↩ Parent](#policyserver-1)</sup></sup>



PolicyServerStatus defines the observed state of PolicyServer

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#policyserverstatusconditionsindex-1">conditions</a></b></td>
        <td>[]object</td>
        <td>
          Conditions represent the observed conditions of the PolicyServer resource.  Known .status.conditions.types are: "PolicyServerSecretReconciled", "PolicyServerDeploymentReconciled" and "PolicyServerServiceReconciled"<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### PolicyServer.status.conditions[index]
<sup><sup>[↩ Parent](#policyserverstatus-1)</sup></sup>



Condition contains details for one aspect of the current state of this API Resource. --- This struct is intended for direct use as an array at the field path .status.conditions.  For example, 
 type FooStatus struct{ // Represents the observations of a foo's current state. // Known .status.conditions.type are: "Available", "Progressing", and "Degraded" // +patchMergeKey=type // +patchStrategy=merge // +listType=map // +listMapKey=type Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` 
 // other fields }

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another. This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition. This may be an empty string.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition. Producers of specific condition types may define expected values and meanings for this field, and whether the values are considered a guaranteed API. The value should be a CamelCase string. This field may not be empty.<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase. --- Many .condition.type values are consistent across resources like Available, but because arbitrary conditions can be useful (see .node.status.conditions), the ability to deconflict is important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon. For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date with respect to the current state of the instance.<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>