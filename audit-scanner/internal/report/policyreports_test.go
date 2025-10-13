package report

import (
	"testing"
	"time"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestNewPolicyReport(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetNamespace("namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetName("test-pod")
	resource.SetResourceVersion("12345")

	policyReport := NewPolicyReport("runUID", resource)
	policyReport.report.Summary.Skip = 1
	policyReport.report.Summary.Error = 1

	assert.Equal(t, "uid", policyReport.report.ObjectMeta.Name)
	assert.Equal(t, "namespace", policyReport.report.ObjectMeta.Namespace)
	assert.Equal(t, "kubewarden", policyReport.report.ObjectMeta.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "v2", policyReport.report.ObjectMeta.Labels["kubewarden.io/policyreport-version"])
	assert.Equal(t, "runUID", policyReport.report.ObjectMeta.Labels[constants.AuditScannerRunUIDLabel])

	assert.Equal(t, "v1", policyReport.report.ObjectMeta.OwnerReferences[0].APIVersion)
	assert.Equal(t, "Pod", policyReport.report.ObjectMeta.OwnerReferences[0].Kind)
	assert.Equal(t, "test-pod", policyReport.report.ObjectMeta.OwnerReferences[0].Name)
	assert.Equal(t, types.UID("uid"), policyReport.report.ObjectMeta.OwnerReferences[0].UID)

	assert.Equal(t, "v1", policyReport.report.Scope.APIVersion)
	assert.Equal(t, "Pod", policyReport.report.Scope.Kind)
	assert.Equal(t, "test-pod", policyReport.report.Scope.Name)
	assert.Equal(t, types.UID("uid"), policyReport.report.Scope.UID)
	assert.Equal(t, "12345", policyReport.report.Scope.ResourceVersion)

	assert.Equal(t, 1, policyReport.report.Summary.Skip)
	assert.Equal(t, 1, policyReport.report.Summary.Error)

	assert.Empty(t, policyReport.report.Results)
}

func TestAddResultToPolicyReport(t *testing.T) {
	tests := []struct {
		name            string
		admissionReview *admissionv1.AdmissionReview
		errored         bool
		expectedPass    int
		expectedFail    int
		expectedWarn    int
		expectedError   int
	}{
		{
			name: "Allowed",
			admissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: true,
					Result:  &metav1.Status{Message: "The request was allowed"},
				},
			},
			errored:       false,
			expectedPass:  1,
			expectedFail:  0,
			expectedWarn:  0,
			expectedError: 0,
		},
		{
			name: "Errored",
			admissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Message: "Something went wrong"},
				},
			},
			errored:       true,
			expectedPass:  0,
			expectedFail:  0,
			expectedWarn:  0,
			expectedError: 1,
		},
		{
			name:            "Errored no AdmissionReview",
			admissionReview: nil,
			errored:         true,
			expectedPass:    0,
			expectedFail:    0,
			expectedWarn:    0,
			expectedError:   1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := &policiesv1.AdmissionPolicy{}
			policyReport := NewPolicyReport("runUID", unstructured.Unstructured{})

			policyReport.AddResult(policy, test.admissionReview, test.errored)

			assert.Len(t, policyReport.report.Results, 1)

			if test.admissionReview != nil {
				assert.Equal(t, test.admissionReview.Response.Result.Message, policyReport.report.Results[0].Description)
			}
			assert.Equal(t, test.expectedPass, policyReport.report.Summary.Pass)
			assert.Equal(t, test.expectedFail, policyReport.report.Summary.Fail)
			assert.Equal(t, test.expectedWarn, policyReport.report.Summary.Warn)
			assert.Equal(t, test.expectedError, policyReport.report.Summary.Error)
		})
	}
}

func TestNewClusterPolicyReport(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Namespace")
	resource.SetResourceVersion("12345")

	clusterPolicyReport := NewClusterPolicyReport("runUID", resource).report
	clusterPolicyReport.Summary.Skip = 1
	clusterPolicyReport.Summary.Error = 1

	assert.Equal(t, "uid", clusterPolicyReport.ObjectMeta.Name)
	assert.Equal(t, "kubewarden", clusterPolicyReport.ObjectMeta.Labels[labelAppManagedBy])
	assert.Equal(t, "v2", clusterPolicyReport.ObjectMeta.Labels["kubewarden.io/policyreport-version"])
	assert.Equal(t, "runUID", clusterPolicyReport.ObjectMeta.Labels[constants.AuditScannerRunUIDLabel])

	assert.Equal(t, "v1", clusterPolicyReport.ObjectMeta.OwnerReferences[0].APIVersion)
	assert.Equal(t, "Namespace", clusterPolicyReport.ObjectMeta.OwnerReferences[0].Kind)
	assert.Equal(t, "test-namespace", clusterPolicyReport.ObjectMeta.OwnerReferences[0].Name)
	assert.Equal(t, types.UID("uid"), clusterPolicyReport.ObjectMeta.OwnerReferences[0].UID)

	assert.Equal(t, "v1", clusterPolicyReport.Scope.APIVersion)
	assert.Equal(t, "Namespace", clusterPolicyReport.Scope.Kind)
	assert.Equal(t, "test-namespace", clusterPolicyReport.Scope.Name)
	assert.Equal(t, types.UID("uid"), clusterPolicyReport.Scope.UID)
	assert.Equal(t, "12345", clusterPolicyReport.Scope.ResourceVersion)

	assert.Equal(t, 1, clusterPolicyReport.Summary.Skip)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Error)

	assert.Empty(t, clusterPolicyReport.Results)
}

func TestAddResultToClusterPolicyReport(t *testing.T) {
	policy := &policiesv1.AdmissionPolicy{}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: false,
			Result:  &metav1.Status{Message: "The request was rejected"},
		},
	}

	clusterPolicyReport := NewClusterPolicyReport("runUID", unstructured.Unstructured{})
	clusterPolicyReport.AddResult(policy, admissionReview, false)

	assert.Len(t, clusterPolicyReport.report.Results, 1)
	assert.Equal(t, 0, clusterPolicyReport.report.Summary.Pass)
	assert.Equal(t, 1, clusterPolicyReport.report.Summary.Fail)
	assert.Equal(t, 0, clusterPolicyReport.report.Summary.Warn)
	assert.Equal(t, 0, clusterPolicyReport.report.Summary.Error)
}

func TestNewPolicyReportResult(t *testing.T) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}

	tests := []struct {
		name            string
		policy          policiesv1.Policy
		admissionReview *admissionv1.AdmissionReview
		errored         bool
		expectedResult  *wgpolicy.PolicyReportResult
	}{
		{
			name: "Validating policy, allowed response",
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "1",
					Name:            "policy-name",
					Annotations: map[string]string{
						policiesv1.AnnotationSeverity: severityLow,
					},
				},
				Spec: policiesv1.ClusterAdmissionPolicySpec{
					PolicySpec: policiesv1.PolicySpec{
						Mutating: false,
					},
				},
			},
			admissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: true,
					Result:  nil,
				},
			},
			errored: false,
			expectedResult: &wgpolicy.PolicyReportResult{
				Source:          policyReportSource,
				Policy:          "clusterwide-policy-name",
				Severity:        severityLow,
				Result:          statusPass,
				Timestamp:       now,
				Scored:          true,
				SubjectSelector: &metav1.LabelSelector{},
				Description:     "",
				Properties: map[string]string{
					propertyPolicyUID:             "policy-uid",
					propertyPolicyResourceVersion: "1",
					propertyPolicyName:            "policy-name",
					typeValidating:                valueTypeTrue,
				},
			},
		},
		{
			name: "Mutating policy, rejected response",
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "1",
					Name:            "policy-name",
					Namespace:       "policy-namespace",
					Annotations: map[string]string{
						policiesv1.AnnotationSeverity: severityCritical,
					},
				},
				Spec: policiesv1.AdmissionPolicySpec{
					PolicySpec: policiesv1.PolicySpec{
						Mutating: true,
					},
				},
			},
			admissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Message: "The request was rejected"},
				},
			},
			errored: false,
			expectedResult: &wgpolicy.PolicyReportResult{
				Source:          policyReportSource,
				Policy:          "namespaced-policy-namespace-policy-name",
				Severity:        severityCritical,
				Result:          statusFail,
				Timestamp:       now,
				Scored:          true,
				SubjectSelector: &metav1.LabelSelector{},
				Description:     "The request was rejected",
				Properties: map[string]string{
					propertyPolicyUID:             "policy-uid",
					propertyPolicyResourceVersion: "1",
					propertyPolicyName:            "policy-name",
					propertyPolicyNamespace:       "policy-namespace",
					typeMutating:                  valueTypeTrue,
				},
			},
		},
		{
			name: "Validating policy in monitor mode, response error",
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "1",
					Name:            "policy-name",
					Namespace:       "policy-namespace",
					Annotations: map[string]string{
						policiesv1.AnnotationSeverity: severityInfo,
					},
				},
				Spec: policiesv1.AdmissionPolicySpec{
					PolicySpec: policiesv1.PolicySpec{
						Mutating: false,
						Mode:     policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor),
					},
				},
			},
			admissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: true,
					Result: &metav1.Status{
						Message: "The server is on vacation",
						Code:    500,
					},
				},
			},
			errored: true,
			expectedResult: &wgpolicy.PolicyReportResult{
				Source:          policyReportSource,
				Policy:          "namespaced-policy-namespace-policy-name",
				Severity:        severityInfo,
				Result:          statusError,
				Timestamp:       now,
				Scored:          true,
				SubjectSelector: &metav1.LabelSelector{},
				Description:     "The server is on vacation",
				Properties: map[string]string{
					propertyPolicyUID:             "policy-uid",
					propertyPolicyResourceVersion: "1",
					propertyPolicyName:            "policy-name",
					propertyPolicyNamespace:       "policy-namespace",
					typeValidating:                valueTypeTrue,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := newPolicyReportResult(test.policy, test.admissionReview, test.errored, now)
			assert.Equal(t, test.expectedResult, result)
		})
	}
}
