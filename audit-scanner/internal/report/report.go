package report

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type PolicyReport struct {
	v1alpha2.PolicyReport
}
type ClusterPolicyReport struct {
	v1alpha2.ClusterPolicyReport
}

type RInterface interface {
	metav1.Object
	// GetType returns the type of the PolicyReport
	GetType() ResourceType
	// AddResult adds a PolicyReportResult to the policy report. This result
	// includes policy info and resource under audit
	AddResult(policiesv1.Policy, unstructured.Unstructured, *admv1.AdmissionReview, error)
}

// ResourceType Enum defined for PolicyReport
type ResourceType = string

// ReportType Enum
const (
	PolicyReportType        ResourceType = "PolicyReport"
	ClusterPolicyReportType ResourceType = "ClusterPolicyReport"
)

// Status specifies state of a policy result
const (
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusWarn  = "warn"
	StatusError = "error"
	StatusSkip  = "skip"
)

func NewCPR(name string) *ClusterPolicyReport {
	return &ClusterPolicyReport{
		ClusterPolicyReport: v1alpha2.ClusterPolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              PrefixNameClusterPolicyReport + name,
				CreationTimestamp: metav1.Now(),
			},
			Summary: v1alpha2.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
			Results: []*v1alpha2.PolicyReportResult{},
		},
	}
}

func NewPR(namespace *v1.Namespace) *PolicyReport {
	return &PolicyReport{
		PolicyReport: v1alpha2.PolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              PrefixNamePolicyReport + namespace.Name,
				Namespace:         namespace.Name,
				CreationTimestamp: metav1.Now(),
			},
			Scope: &v1.ObjectReference{
				Kind:            namespace.Kind,
				Namespace:       "",
				Name:            namespace.Name,
				UID:             namespace.UID,
				APIVersion:      namespace.APIVersion,
				ResourceVersion: namespace.ResourceVersion,
			},
			Summary: v1alpha2.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
			Results: []*v1alpha2.PolicyReportResult{},
		},
	}
}

func (r *ClusterPolicyReport) GetType() ResourceType {
	return ClusterPolicyReportType
}

func (r *PolicyReport) GetType() ResourceType {
	return PolicyReportType
}

func (r *PolicyReport) AddResult(policy policiesv1.Policy, resource unstructured.Unstructured, auditResponse *admv1.AdmissionReview, responseErr error) {
	result := newResult(policy, resource, auditResponse, responseErr)
	switch result.Result {
	case StatusFail:
		r.Summary.Fail++
	case StatusError:
		r.Summary.Error++
	case StatusPass:
		r.Summary.Pass++
	}
	r.Results = append(r.Results, result)
}

func (r *ClusterPolicyReport) AddResult(policy policiesv1.Policy, resource unstructured.Unstructured, auditResponse *admv1.AdmissionReview, responseErr error) {
	result := newResult(policy, resource, auditResponse, responseErr)
	switch result.Result {
	case StatusFail:
		r.Summary.Fail++
	case StatusError:
		r.Summary.Error++
	case StatusPass:
		r.Summary.Pass++
	}
	r.Results = append(r.Results, result)
}

func newResult(policy policiesv1.Policy, resource unstructured.Unstructured, auditResponse *admv1.AdmissionReview, responseErr error) *v1alpha2.PolicyReportResult {
	var result v1alpha2.PolicyResult
	var description string
	if responseErr != nil {
		result = StatusError
		description = auditResponse.Response.Result.Message
	} else {
		if auditResponse.Response.Allowed {
			result = StatusPass
		} else {
			result = StatusFail
			description = auditResponse.Response.Result.Message
		}
	}

	var name string
	switch policy.GetObjectKind().GroupVersionKind() {
	case schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	}:
		name = "cap-" + policy.GetName()
	case schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicy,
	}:
		name = "ap-" + policy.GetName()
	}

	time := metav1.Now()
	timestamp := *time.ProtoTime()

	resourceObjectReference := &v1.ObjectReference{
		Kind:            resource.GetKind(),
		Namespace:       resource.GetNamespace(),
		Name:            resource.GetName(),
		UID:             resource.GetUID(),
		APIVersion:      resource.GetAPIVersion(),
		ResourceVersion: resource.GetResourceVersion(),
	}

	return &v1alpha2.PolicyReportResult{
		Source: PolicyReportSource,
		Policy: name, // either cap-policy_name or ap-policy_name
		// Timestamp shouldn't be used in go structs, and only gives seconds
		// https://github.com/kubernetes/apimachinery/blob/v0.27.2/pkg/apis/meta/v1/time_proto.go#LL48C9-L48C9
		Timestamp:   timestamp,                                      // time the result was found
		Result:      result,                                         // pass, fail, error
		Subjects:    []*v1.ObjectReference{resourceObjectReference}, // reference to object evaluated
		Description: description,                                    // output message of the policy
	}
}
