/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ClusterAdmissionPolicySpec defines the desired state of ClusterAdmissionPolicy
type ClusterAdmissionPolicySpec struct {
	// PolicyServer identifies an existing PolicyServer resource.
	// +kubebuilder:default:=default
	// +optional
	PolicyServer string `json:"policyServer"`

	// Module is the location of the WASM module to be loaded. Can be a
	// local file (file://), a remote file served by an HTTP server
	// (http://, https://), or an artifact served by an OCI-compatible
	// registry (registry://).
	Module string `json:"module,omitempty"`

	// Settings is a free-form object that contains the policy configuration
	// values.
	// +optional
	// +nullable
	// +kubebuilder:pruning:PreserveUnknownFields
	// x-kubernetes-embedded-resource: false
	Settings runtime.RawExtension `json:"settings,omitempty"`

	// Rules describes what operations on what resources/subresources the webhook cares about.
	// The webhook cares about an operation if it matches _any_ Rule.
	Rules []admissionregistrationv1.RuleWithOperations `json:"rules"`

	// FailurePolicy defines how unrecognized errors and timeout errors from the
	// policy are handled. Allowed values are "Ignore" or "Fail".
	// * "Ignore" means that an error calling the webhook is ignored and the API
	//   request is allowed to continue.
	// * "Fail" means that an error calling the webhook causes the admission to
	//   fail and the API request to be rejected.
	// The default behaviour is "Fail"
	// +optional
	FailurePolicy *admissionregistrationv1.FailurePolicyType `json:"failurePolicy,omitempty"`

	// Mutating indicates whether a policy has the ability to mutate
	// incoming requests or not.
	Mutating bool `json:"mutating"`

	// matchPolicy defines how the "rules" list is used to match incoming requests.
	// Allowed values are "Exact" or "Equivalent".
	//
	// - Exact: match a request only if it exactly matches a specified rule.
	// For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
	// but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
	// a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
	//
	// - Equivalent: match a request if modifies a resource listed in rules, even via another API group or version.
	// For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
	// and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
	// a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
	//
	// Defaults to "Equivalent"
	// +optional
	MatchPolicy *admissionregistrationv1.MatchPolicyType `json:"matchPolicy,omitempty"`

	// NamespaceSelector decides whether to run the webhook on an object based
	// on whether the namespace for that object matches the selector. If the
	// object itself is a namespace, the matching is performed on
	// object.metadata.labels. If the object is another cluster scoped resource,
	// it never skips the webhook.
	//
	// For example, to run the webhook on any objects whose namespace is not
	// associated with "runlevel" of "0" or "1";  you will set the selector as
	// follows:
	// "namespaceSelector": {
	//   "matchExpressions": [
	//     {
	//       "key": "runlevel",
	//       "operator": "NotIn",
	//       "values": [
	//         "0",
	//         "1"
	//       ]
	//     }
	//   ]
	// }
	//
	// If instead you want to only run the webhook on any objects whose
	// namespace is associated with the "environment" of "prod" or "staging";
	// you will set the selector as follows:
	// "namespaceSelector": {
	//   "matchExpressions": [
	//     {
	//       "key": "environment",
	//       "operator": "In",
	//       "values": [
	//         "prod",
	//         "staging"
	//       ]
	//     }
	//   ]
	// }
	//
	// See
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
	// for more examples of label selectors.
	//
	// Default to the empty LabelSelector, which matches everything.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// ObjectSelector decides whether to run the webhook based on if the
	// object has matching labels. objectSelector is evaluated against both
	// the oldObject and newObject that would be sent to the webhook, and
	// is considered to match if either object matches the selector. A null
	// object (oldObject in the case of create, or newObject in the case of
	// delete) or an object that cannot have labels (like a
	// DeploymentRollback or a PodProxyOptions object) is not considered to
	// match.
	// Use the object selector only if the webhook is opt-in, because end
	// users may skip the admission webhook by setting the labels.
	// Default to the empty LabelSelector, which matches everything.
	// +optional
	ObjectSelector *metav1.LabelSelector `json:"objectSelector,omitempty"`

	// SideEffects states whether this webhook has side effects.
	// Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
	// Webhooks with side effects MUST implement a reconciliation system, since a request may be
	// rejected by a future step in the admission change and the side effects therefore need to be undone.
	// Requests with the dryRun attribute will be auto-rejected if they match a webhook with
	// sideEffects == Unknown or Some.
	SideEffects *admissionregistrationv1.SideEffectClass `json:"sideEffects,omitempty"`

	// TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
	// the webhook call will be ignored or the API call will fail based on the
	// failure policy.
	// The timeout value must be between 1 and 30 seconds.
	// Default to 10 seconds.
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
}

const (
	// PolicyServerConfigMapReconciled represents the condition of the
	// Policy Server ConfigMap reconciliation
	PolicyServerConfigMapReconciled PolicyConditionType = "PolicyServerConfigMapReconciled"
	// ClusterAdmissionPolicyActive represents the condition of the Policy
	// admission webhook being registered
	ClusterAdmissionPolicyActive PolicyConditionType = "PolicyActive"
)

// +kubebuilder:validation:Enum=unscheduled;unschedulable;pending;active
type ClusterAdmissionPolicyStatusEnum string

const (
	// ClusterAdmissionPolicyStatusUnscheduled is a transient state that will continue
	// to unschedulable or pending. This is the default state.
	ClusterAdmissionPolicyStatusUnscheduled ClusterAdmissionPolicyStatusEnum = "unscheduled"
	// ClusterAdmissionPolicyStatusUnschedulable informs that policy server where to
	// schedule the policy is not available
	ClusterAdmissionPolicyStatusUnschedulable ClusterAdmissionPolicyStatusEnum = "unschedulable"
	// ClusterAdmissionPolicyStatusPending informs that the policy server exists,
	// we are reconciling all resources
	ClusterAdmissionPolicyStatusPending ClusterAdmissionPolicyStatusEnum = "pending"
	// ClusterAdmissionPolicyStatusActive informs that the k8s API server should be
	// forwarding admission review objects to the policy
	ClusterAdmissionPolicyStatusActive ClusterAdmissionPolicyStatusEnum = "active"
)

// ClusterAdmissionPolicyStatus defines the observed state of ClusterAdmissionPolicy
type ClusterAdmissionPolicyStatus struct {
	// PolicyStatus represents whether this ClusterAdmissionPolicy is unscheduled,
	// unschedulable, pending, or active.
	PolicyStatus ClusterAdmissionPolicyStatusEnum `json:"policyStatus"`
	// Conditions represent the observed conditions of the
	// ClusterAdmissionPolicy resource.  Known .status.conditions.types
	// are: "PolicyServerSecretReconciled",
	// "PolicyServerConfigMapReconciled",
	// "PolicyServerDeploymentReconciled",
	// "PolicyServerServiceReconciled" and
	// "ClusterAdmissionPolicyActive"
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ClusterAdmissionPolicy is the Schema for the clusteradmissionpolicies API
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:storageversion
//+kubebuilder:printcolumn:name="Mutating",type=boolean,JSONPath=`.spec.mutating`,description="Whether the policy is mutating"
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.policyStatus`,description="Status of the policy"
//nolint:lll
type ClusterAdmissionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterAdmissionPolicySpec   `json:"spec,omitempty"`
	Status ClusterAdmissionPolicyStatus `json:"status,omitempty"`
}

// ClusterAdmissionPolicyList contains a list of ClusterAdmissionPolicy
//+kubebuilder:object:root=true
type ClusterAdmissionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterAdmissionPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterAdmissionPolicy{}, &ClusterAdmissionPolicyList{})
}
