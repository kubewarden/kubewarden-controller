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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AdmissionPolicySpec defines the desired state of AdmissionPolicy
type AdmissionPolicySpec struct {
	// PolicyServer identifies an existing PolicyServer resource.
	// +kubebuilder:default:=default
	// +optional
	PolicyServer string `json:"policyServer"`

	// Module is the location of the WASM module to be loaded. Can be a
	// local file (file://), a remote file served by an HTTP server
	// (http://, https://), or an artifact served by an OCI-compatible
	// registry (registry://).
	Module string `json:"module,omitempty"`

	// Mode defines the execution mode of this policy. Can be set to
	// either "protect" or "monitor". If it's empty, it is defaulted to
	// "protect".
	// Transitioning this setting from "monitor" to "protect" is
	// allowed, but is disallowed to transition from "protect" to
	// "monitor". To perform this transition, the policy should be
	// recreated in "monitor" mode instead.
	// +kubebuilder:default:=protect
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`

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

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced
//+kubebuilder:storageversion
//+kubebuilder:printcolumn:name="Policy Server",type=string,JSONPath=`.spec.policyServer`,description="Bound to Policy Server"
//+kubebuilder:printcolumn:name="Mutating",type=boolean,JSONPath=`.spec.mutating`,description="Whether the policy is mutating"
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.policyStatus`,description="Status of the policy"
// AdmissionPolicy is the Schema for the admissionpolicies API
type AdmissionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AdmissionPolicySpec `json:"spec,omitempty"`
	Status PolicyStatus        `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AdmissionPolicyList contains a list of AdmissionPolicy
type AdmissionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdmissionPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AdmissionPolicy{}, &AdmissionPolicyList{})
}

func (p *AdmissionPolicy) SetStatus(status PolicyStatusEnum) {
	p.Status.PolicyStatus = status
}

func (p *AdmissionPolicy) GetPolicyMode() PolicyMode {
	return p.Spec.Mode
}

func (p *AdmissionPolicy) GetModule() string {
	return p.Spec.Module
}

func (p *AdmissionPolicy) IsMutating() bool {
	return p.Spec.Mutating
}

func (p *AdmissionPolicy) GetSettings() runtime.RawExtension {
	return p.Spec.Settings
}

func (p *AdmissionPolicy) GetStatus() *PolicyStatus {
	return &p.Status
}

func (p *AdmissionPolicy) DeepCopyPolicy() client.Object {
	return p.DeepCopy()
}

func (p *AdmissionPolicy) GetSideEffects() *admissionregistrationv1.SideEffectClass {
	return p.Spec.SideEffects
}

// GetRules returns all rules. Scope is namespaced since AdmissionPolicy just watch for namespace resources
func (p *AdmissionPolicy) GetRules() []admissionregistrationv1.RuleWithOperations {
	namespacedScopeV1 := admissionregistrationv1.NamespacedScope
	rules := make([]admissionregistrationv1.RuleWithOperations, 0)
	for _, rule := range p.Spec.Rules {
		rule.Scope = &namespacedScopeV1
		rules = append(rules, rule)
	}

	return rules
}

func (p *AdmissionPolicy) GetFailurePolicy() *admissionregistrationv1.FailurePolicyType {
	return p.Spec.FailurePolicy
}

func (p *AdmissionPolicy) GetMatchPolicy() *admissionregistrationv1.MatchPolicyType {
	return p.Spec.MatchPolicy
}

// GetNamespaceSelector returns the namespace of the AdmissionPolicy since it is the only namespace we want the policy to be applied to.
func (p *AdmissionPolicy) GetNamespaceSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{"kubernetes.io/metadata.name": p.ObjectMeta.Namespace},
	}
}

func (p *AdmissionPolicy) GetObjectSelector() *metav1.LabelSelector {
	return p.Spec.ObjectSelector
}

func (p *AdmissionPolicy) GetTimeoutSeconds() *int32 {
	return p.Spec.TimeoutSeconds
}

func (p *AdmissionPolicy) GetObjectMeta() *metav1.ObjectMeta {
	return &p.ObjectMeta
}

func (p *AdmissionPolicy) GetPolicyServer() string {
	return p.Spec.PolicyServer
}
