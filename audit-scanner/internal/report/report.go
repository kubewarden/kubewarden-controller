package report

import (
	"time"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// CrdKind represents the kind of report to use to store audit results.
type CrdKind int

const (
	ReportKindOpenReport CrdKind = iota
	ReportKindPolicyReport
)

// Report interface to abstract which kind of report are under use. This is useful
// to support both PolicyReport and OpenReport without duplicating code.
type Report interface {
	SetSkipPolicies(n int)
	SetErrorPolicies(n int)
	AddResult(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview, errored bool)
}

type PolicyReport struct {
	report *wgpolicy.PolicyReport
}

type ClusterPolicyReport struct {
	report *wgpolicy.ClusterPolicyReport
}

func NewReportOfKind(kind CrdKind, runUID string, resource unstructured.Unstructured) Report {
	if kind == ReportKindPolicyReport {
		return NewPolicyReport(runUID, resource)
	}
	return NewOpenReport(runUID, resource)
}

func NewClusterReportOfKind(kind CrdKind, runUID string, resource unstructured.Unstructured) Report {
	if kind == ReportKindPolicyReport {
		return NewClusterPolicyReport(runUID, resource)
	}
	return NewClusterOpenReport(runUID, resource)
}

// NewPolicyReport creates a new PolicyReport from a given resource.
// Deprecated: use NewReport instead. wgpolicy.PolicyReport is deprecated in favor of openreports.Report.
func NewPolicyReport(runUID string, resource unstructured.Unstructured) *PolicyReport {
	objMeta := getReportObjectMeta(runUID, resource)
	objMeta.Namespace = resource.GetNamespace()
	return &PolicyReport{
		report: &wgpolicy.PolicyReport{
			ObjectMeta: objMeta,
			Scope:      getReportScope(resource),
			Summary: wgpolicy.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
		},
	}
}

func (r *PolicyReport) AddResult(
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newPolicyReportResult(policy, admissionReview, errored, now)
	switch result.Result {
	case statusFail:
		r.report.Summary.Fail++
	case statusError:
		r.report.Summary.Error++
	case statusPass:
		r.report.Summary.Pass++
	}
	r.report.Results = append(r.report.Results, result)
}

func (r *PolicyReport) SetSkipPolicies(skippedPoliciesNumber int) {
	r.report.Summary.Skip = skippedPoliciesNumber
}

func (r *PolicyReport) SetErrorPolicies(erroredPoliciesNumber int) {
	r.report.Summary.Error = erroredPoliciesNumber
}

// NewClusterPolicyReport creates a new ClusterPolicyReport from a given resource.
// Deprecated: use NewClusterReport instead. wgpolicy.ClusterPolicyReport is deprecated in favor of openreports.ClusterReport.
func NewClusterPolicyReport(runUID string, resource unstructured.Unstructured) *ClusterPolicyReport {
	return &ClusterPolicyReport{
		report: &wgpolicy.ClusterPolicyReport{
			ObjectMeta: getReportObjectMeta(runUID, resource),
			Scope:      getReportScope(resource),
			Summary: wgpolicy.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
		},
	}
}

func (r *ClusterPolicyReport) AddResult(
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newPolicyReportResult(policy, admissionReview, errored, now)
	switch result.Result {
	case statusFail:
		r.report.Summary.Fail++
	case statusError:
		r.report.Summary.Error++
	case statusPass:
		r.report.Summary.Pass++
	}
	r.report.Results = append(r.report.Results, result)
}

func (r *ClusterPolicyReport) SetSkipPolicies(skippedPoliciesNumber int) {
	r.report.Summary.Skip = skippedPoliciesNumber
}

func (r *ClusterPolicyReport) SetErrorPolicies(erroredPoliciesNumber int) {
	r.report.Summary.Error = erroredPoliciesNumber
}

func newPolicyReportResult(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview, errored bool, timestamp metav1.Timestamp) *wgpolicy.PolicyReportResult {
	category, message := getCategoryAndMessage(policy, admissionReview)

	return &wgpolicy.PolicyReportResult{
		Source:          policyReportSource,
		Policy:          policy.GetUniqueName(),
		Category:        category,
		Severity:        wgpolicy.PolicyResultSeverity(computePolicyResultSeverity(policy)),   // either info for monitor or empty
		Timestamp:       timestamp,                                                            // time the result was computed
		Result:          wgpolicy.PolicyResult(computePolicyResult(errored, admissionReview)), // pass, fail, error
		Scored:          true,
		SubjectSelector: &metav1.LabelSelector{},
		// This field is marshalled to `message`
		Description: message,
		Properties:  computeProperties(policy),
	}
}

func getCategoryAndMessage(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview) (string, string) {
	var category string
	if c, present := policy.GetCategory(); present {
		category = c
	}

	var message string
	// We need to check if Result is not nil because this field is
	// optional. If the policy returns "allowed" to the admissionReview,
	// the Result field is not checked by Kubernetes.
	// https://pkg.go.dev/k8s.io/api@v0.29.2/admission/v1#AdmissionResponse
	if admissionReview != nil &&
		admissionReview.Response != nil &&
		admissionReview.Response.Result != nil {
		// Mesage contains the human-readable error message if Response.Result.Code == 500
		// or the reason why the policy returned a failure
		message = admissionReview.Response.Result.Message
	}
	return category, message
}

func computePolicyResult(errored bool, admissionReview *admissionv1.AdmissionReview) string {
	if errored {
		return statusError
	}
	if admissionReview.Response.Allowed {
		return statusPass
	}
	return statusFail
}

func computePolicyResultSeverity(policy policiesv1.Policy) string {
	if policy.GetPolicyMode() == policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor) {
		return severityInfo
	}

	if s, present := policy.GetSeverity(); present {
		return s
	}

	return ""
}

func computeProperties(policy policiesv1.Policy) map[string]string {
	properties := map[string]string{}
	if policy.IsMutating() {
		properties[typeMutating] = valueTypeTrue
	} else {
		properties[typeValidating] = valueTypeTrue
	}
	if policy.IsContextAware() {
		properties[typeContextAware] = valueTypeTrue
	}
	// The policy resource version and the policy UID are used to check if the
	// same result can be reused in the next scan
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
	properties[propertyPolicyResourceVersion] = policy.GetResourceVersion()
	properties[propertyPolicyUID] = string(policy.GetUID())
	properties[propertyPolicyName] = policy.GetName()
	if policy.GetNamespace() != "" {
		properties[propertyPolicyNamespace] = policy.GetNamespace()
	}

	return properties
}

func getReportObjectMeta(runUID string, resource unstructured.Unstructured) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: string(resource.GetUID()),
		Labels: map[string]string{
			labelAppManagedBy:                 labelApp,
			labelPolicyReportVersion:          labelPolicyReportVersionValue,
			constants.AuditScannerRunUIDLabel: runUID,
		},
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: resource.GetAPIVersion(),
				Kind:       resource.GetKind(),
				Name:       resource.GetName(),
				UID:        resource.GetUID(),
			},
		},
	}
}

func getReportScope(resource unstructured.Unstructured) *corev1.ObjectReference {
	return &corev1.ObjectReference{
		APIVersion:      resource.GetAPIVersion(),
		Kind:            resource.GetKind(),
		Namespace:       resource.GetNamespace(),
		Name:            resource.GetName(),
		UID:             resource.GetUID(),
		ResourceVersion: resource.GetResourceVersion(),
	}
}
