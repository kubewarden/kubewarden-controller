package v1

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:validation:Enum=unscheduled;scheduled;pending;active
type PolicyStatusEnum string

const (
	// PolicyStatusUnscheduled is a transient state that will continue
	// to scheduled. This is the default state if no policy server is
	// assigned.
	PolicyStatusUnscheduled PolicyStatusEnum = "unscheduled"
	// PolicyStatusScheduled is a transient state that will continue to
	// pending. This is the default state if a policy server is
	// assigned.
	PolicyStatusScheduled PolicyStatusEnum = "scheduled"
	// PolicyStatusPending informs that the policy server exists,
	// we are reconciling all resources
	PolicyStatusPending PolicyStatusEnum = "pending"
	// PolicyStatusActive informs that the k8s API server should be
	// forwarding admission review objects to the policy
	PolicyStatusActive PolicyStatusEnum = "active"
)

// +kubebuilder:validation:Enum=protect;monitor;unknown
type PolicyModeStatus string

const (
	PolicyModeStatusProtect PolicyModeStatus = "protect"
	PolicyModeStatusMonitor PolicyModeStatus = "monitor"
	PolicyModeStatusUnknown PolicyModeStatus = "unknown"
)

type PolicyConditionType string

const (
	// PolicyActive represents the condition of the Policy admission
	// webhook been registered
	PolicyActive PolicyConditionType = "PolicyActive"
	// PolicyServerConfigurationUpToDate represents the condition of the
	// associated Policy Server having the latest configuration up to
	// date regarding this policy
	PolicyServerConfigurationUpToDate PolicyConditionType = "PolicyServerConfigurationUpToDate"
	// PolicyUniquelyReachable represents the condition of the latest
	// applied policy being uniquely accessible. This means that after a
	// policy has been deployed or modified, after this condition is met
	// for this policy, only the latest instance of the policy can be
	// reached through policy server where it is scheduled.
	PolicyUniquelyReachable PolicyConditionType = "PolicyUniquelyReachable"
)

// PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy
type PolicyStatus struct {
	// PolicyStatus represents the observed status of the policy
	PolicyStatus PolicyStatusEnum `json:"policyStatus"`
	// PolicyMode represents the observed policy mode of this policy in
	// the associated PolicyServer configuration
	PolicyMode PolicyModeStatus `json:"mode,omitempty"`
	// Conditions represent the observed conditions of the
	// ClusterAdmissionPolicy resource.  Known .status.conditions.types
	// are: "PolicyServerSecretReconciled",
	// "PolicyServerConfigMapReconciled",
	// "PolicyServerDeploymentReconciled",
	// "PolicyServerServiceReconciled" and
	// "AdmissionPolicyActive"
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:generate:=false
type Policy interface {
	client.Object
	GetPolicyMode() PolicyMode
	SetPolicyModeStatus(policyMode PolicyModeStatus)
	GetModule() string
	IsMutating() bool
	GetSettings() runtime.RawExtension
	GetStatus() *PolicyStatus
	SetStatus(status PolicyStatusEnum)
	CopyInto(object *Policy)
	GetSideEffects() *admissionregistrationv1.SideEffectClass
	GetRules() []admissionregistrationv1.RuleWithOperations
	GetFailurePolicy() *admissionregistrationv1.FailurePolicyType
	GetMatchPolicy() *admissionregistrationv1.MatchPolicyType
	GetNamespaceSelector(deploymentNamespace string) *metav1.LabelSelector
	GetObjectSelector() *metav1.LabelSelector
	GetTimeoutSeconds() *int32
	GetObjectMeta() *metav1.ObjectMeta
	GetPolicyServer() string
	GetUniqueName() string
}
