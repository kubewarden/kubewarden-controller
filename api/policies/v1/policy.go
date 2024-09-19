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
	// we are reconciling all resources.
	PolicyStatusPending PolicyStatusEnum = "pending"
	// PolicyStatusActive informs that the k8s API server should be
	// forwarding admission review objects to the policy.
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
	// webhook been registered.
	PolicyActive PolicyConditionType = "PolicyActive"
	// PolicyServerConfigurationUpToDate represents the condition of the
	// associated Policy Server having the latest configuration up to
	// date regarding this policy.
	PolicyServerConfigurationUpToDate PolicyConditionType = "PolicyServerConfigurationUpToDate"
	// PolicyUniquelyReachable represents the condition of the latest
	// applied policy being uniquely accessible. This means that after a
	// policy has been deployed or modified, after this condition is met
	// for this policy, only the latest instance of the policy can be
	// reached through policy server where it is scheduled.
	PolicyUniquelyReachable PolicyConditionType = "PolicyUniquelyReachable"
)

const (
	AnnotationSeverity    string = "io.kubewarden.policy.severity"
	AnnotationCategory    string = "io.kubewarden.policy.category"
	AnnotationTitle       string = "io.artifacthub.displayName"
	AnnotationDescription string = "io.kubewarden.policy.description"
)

// PolicyStatus defines the observed state of ClusterAdmissionPolicy and AdmissionPolicy.
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
type PolicySettings interface {
	GetPolicyMode() PolicyMode
	GetModule() string
	GetSettings() runtime.RawExtension
	GetContextAwareResources() []ContextAwareResource
	GetBackgroundAudit() bool
	GetSeverity() (string, bool)
	GetCategory() (string, bool)
	GetTitle() (string, bool)
	GetDescription() (string, bool)
	GetTimeoutSeconds() *int32
}

// +kubebuilder:object:generate:=false
type PolicyIdentifier interface {
	GetPolicyServer() string
	GetUniqueName() string
}

// +kubebuilder:object:generate:=false
type PolicyAdmissionRegistrationSettings interface {
	GetRules() []admissionregistrationv1.RuleWithOperations
	GetSideEffects() *admissionregistrationv1.SideEffectClass
	GetFailurePolicy() *admissionregistrationv1.FailurePolicyType
	GetMatchPolicy() *admissionregistrationv1.MatchPolicyType
	GetMatchConditions() []admissionregistrationv1.MatchCondition
}

// +kubebuilder:object:generate:=false
type PolicySelectors interface {
	GetNamespaceSelector() *metav1.LabelSelector
	GetObjectSelector() *metav1.LabelSelector
	GetObjectMeta() *metav1.ObjectMeta
}

// +kubebuilder:object:generate:=false
type PolicyBehavior interface {
	IsMutating() bool
	IsContextAware() bool
}

// +kubebuilder:object:generate:=false
type PolicyLifecycle interface {
	SetPolicyModeStatus(policyMode PolicyModeStatus)
	GetStatus() *PolicyStatus
	SetStatus(status PolicyStatusEnum)
}

// +kubebuilder:object:generate:=false
type PolicyCopyable interface {
	CopyInto(object *Policy)
}

// +kubebuilder:object:generate:=false
type Policy interface {
	client.Object
	PolicySettings
	PolicyIdentifier
	PolicyAdmissionRegistrationSettings
	PolicySelectors
	PolicyBehavior
	PolicyLifecycle
	PolicyCopyable
}

// +kubebuilder:object:generate:=false
type PolicyGroup interface {
	Policy
	GetPolicyGroupMembers() PolicyGroupMembers
	GetExpression() string
	GetMessage() string
}
