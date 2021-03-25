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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AdmissionPolicySpec defines the desired state of AdmissionPolicy
type AdmissionPolicySpec struct {
	// Module is the location of the WASM module to be loaded. Can be a
	// local file (file://), a remote file served by an HTTP server
	// (http://, https://), or an artifact served by an OCI-compatible
	// registry (registry://).
	Module string `json:"module,omitempty"`

	// Settings is a free-form object that contains the policy configuration
	// values.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// x-kubernetes-embedded-resource: false
	Settings runtime.RawExtension `json:"settings,omitempty"`

	// APIGroups is a list of API groups that this webhook should be
	// registered against. Empty array or "*" means everything.
	// +optional
	APIGroups []string `json:"apiGroups,omitempty"`

	// APIVersions is a list of API versions that this webhook should be
	// registered against. Empty array or "*" means everything.
	// +optional
	APIVersions []string `json:"apiVersions,omitempty"`

	// Resources is a list of resource types that this webhook should be
	// registered against. Empty array or "*" means everything.
	// +optional
	Resources []string `json:"resources,omitempty"`

	// Operations is a list of operations that this webhook should be
	// registered against. Empty array or "*" means everything.
	// +optional
	Operations []string `json:"operations,omitempty"`

	// FailurePolicy defines how unrecognized errors and timeout errors from the
	// policy are handled. Allowed values are "Ignore" or "Fail".
	// * "Ignore" means that an error calling the webhook is ignored and the API
	//   request is allowed to continue.
	// * "Fail" means that an error calling the webhook causes the admission to
	//   fail and the API request to be rejected.
	// The default behaviour is "Fail"
	// +optional
	FailurePolicy string `json:"failurePolicy,omitempty"`

	// Mutating indicates whether a policy has the ability to mutate
	// incoming requests or not.
	Mutating bool `json:"mutating"`
}

// AdmissionPolicyStatus defines the observed state of AdmissionPolicy
type AdmissionPolicyStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// AdmissionPolicy is the Schema for the admissionpolicies API
type AdmissionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AdmissionPolicySpec   `json:"spec,omitempty"`
	Status AdmissionPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AdmissionPolicyList contains a list of AdmissionPolicy
type AdmissionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdmissionPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AdmissionPolicy{}, &AdmissionPolicyList{})
}
