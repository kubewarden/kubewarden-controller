package policy

import (
	"github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Policy interface {
	client.Object
	GetPolicyMode() v1alpha2.PolicyMode
	GetModule() string
	IsMutating() bool
	GetSettings() runtime.RawExtension
	GetStatus() *v1alpha2.ClusterAdmissionPolicyStatus
	SetStatus(status v1alpha2.ClusterAdmissionPolicyStatusEnum)
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
