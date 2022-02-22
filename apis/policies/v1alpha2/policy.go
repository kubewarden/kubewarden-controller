package v1alpha2

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//+kubebuilder:object:generate:=false
type Policy interface {
	client.Object
	GetPolicyMode() PolicyMode
	GetModule() string
	IsMutating() bool
	GetSettings() runtime.RawExtension
	GetStatus() *ClusterAdmissionPolicyStatus
	SetStatus(status ClusterAdmissionPolicyStatusEnum)
	DeepCopyPolicy() client.Object
	GetSideEffects() *admissionregistrationv1.SideEffectClass
	GetRules() []admissionregistrationv1.RuleWithOperations
	GetFailurePolicy() *admissionregistrationv1.FailurePolicyType
	GetMatchPolicy() *admissionregistrationv1.MatchPolicyType
	GetNamespaceSelector() *metav1.LabelSelector
	GetObjectSelector() *metav1.LabelSelector
	GetTimeoutSeconds() *int32
	GetObjectMeta() *metav1.ObjectMeta
	GetPolicyServer() string
}
