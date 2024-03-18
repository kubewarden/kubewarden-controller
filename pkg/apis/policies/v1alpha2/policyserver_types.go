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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyServerSpec defines the desired state of PolicyServer
type PolicyServerSpec struct {
	// Docker image name.
	Image string `json:"image"`

	// Replicas is the number of desired replicas.
	Replicas int32 `json:"replicas"`

	// Annotations is an unstructured key value map stored with a resource that may be
	// set by external tools to store and retrieve arbitrary metadata. They are not
	// queryable and should be preserved when modifying objects.
	// More info: http://kubernetes.io/docs/user-guide/annotations
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// List of environment variables to set in the container.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Name of the service account associated with the policy server.
	// Namespace service account will be used if not specified.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// Name of ImagePullSecret secret in the same namespace, used for pulling
	// policies from repositories.
	// +optional
	ImagePullSecret string `json:"imagePullSecret,omitempty"`

	// List of insecure URIs to policy repositories. The `insecureSources`
	// content format corresponds with the contents of the `insecure_sources`
	// key in `sources.yaml`. Reference for `sources.yaml` is found in the
	// Kubewarden documentation in the reference section.
	// +optional
	InsecureSources []string `json:"insecureSources,omitempty"`

	// Key value map of registry URIs endpoints to a list of their associated
	// PEM encoded certificate authorities that have to be used to verify the
	// certificate used by the endpoint. The `sourceAuthorities` content format
	// corresponds with the contents of the `source_authorities` key in
	// `sources.yaml`. Reference for `sources.yaml` is found in the Kubewarden
	// documentation in the reference section.
	// +optional
	SourceAuthorities map[string][]string `json:"sourceAuthorities,omitempty"`

	// Name of VerificationConfig configmap in the same namespace, containing
	// Sigstore verification configuration. The configuration must be under a
	// key named verification-config in the Configmap.
	// +optional
	VerificationConfig string `json:"verificationConfig,omitempty"`
}

type ReconciliationTransitionReason string

const (
	// ReconciliationFailed represents a reconciliation failure
	ReconciliationFailed ReconciliationTransitionReason = "ReconciliationFailed"
	// ReconciliationSucceeded represents a reconciliation success
	ReconciliationSucceeded ReconciliationTransitionReason = "ReconciliationSucceeded"
)

type PolicyServerConditionType string

const (
	// PolicyServerCASecretReconciled represents the condition of the
	// Policy Server Secret reconciliation
	PolicyServerCASecretReconciled PolicyServerConditionType = "CASecretReconciled"
	// PolicyServerCARootSecretReconciled represents the condition of the
	// Policy Server CA Root Secret reconciliation
	PolicyServerCARootSecretReconciled PolicyServerConditionType = "CARootSecretReconciled"
	// PolicyServerConfigMapReconciled represents the condition of the
	// Policy Server ConfigMap reconciliation
	PolicyServerConfigMapReconciled PolicyServerConditionType = "ConfigMapReconciled"
	// PolicyServerDeploymentReconciled represents the condition of the
	// Policy Server Deployment reconciliation
	PolicyServerDeploymentReconciled PolicyServerConditionType = "DeploymentReconciled"
	// PolicyServerServiceReconciled represents the condition of the
	// Policy Server Service reconciliation
	PolicyServerServiceReconciled PolicyServerConditionType = "ServiceReconciled"
)

// PolicyServerStatus defines the observed state of PolicyServer
type PolicyServerStatus struct {
	// Conditions represent the observed conditions of the
	// PolicyServer resource.  Known .status.conditions.types
	// are: "PolicyServerSecretReconciled",
	// "PolicyServerDeploymentReconciled" and
	// "PolicyServerServiceReconciled"
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="Replicas",type=string,JSONPath=`.spec.replicas`,description="Policy Server replicas"
//+kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`,description="Policy Server image"

// PolicyServer is the Schema for the policyservers API
type PolicyServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyServerSpec   `json:"spec,omitempty"`
	Status PolicyServerStatus `json:"status,omitempty"`
}

func (ps *PolicyServer) NameWithPrefix() string {
	return "policy-server-" + ps.Name
}

func (ps *PolicyServer) AppLabel() string {
	return "kubewarden-" + ps.NameWithPrefix()
}

//+kubebuilder:object:root=true

// PolicyServerList contains a list of PolicyServer
type PolicyServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyServer{}, &PolicyServerList{})
}
