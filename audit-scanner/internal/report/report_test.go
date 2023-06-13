package report

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestCreateResult(t *testing.T) {
	report := NewClusterPolicyReport("")
	admReviewPass := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{},
		Response: &admv1.AdmissionResponse{
			UID:     "4264aa6a-2d4a-49e6-aed8-156d74678dde",
			Allowed: true,
		},
	}
	admReviewFail := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{},
		Response: &admv1.AdmissionResponse{
			UID:     "4264aa6a-2d4a-49e6-aed8-156d74678dde",
			Allowed: false,
			Result: &metav1.Status{
				Message: "failed, policy-server did boom",
			},
		},
	}
	policy := policiesv1.ClusterAdmissionPolicy{}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	})

	report.AddResult(report.CreateResult(&policy, unstructured.Unstructured{}, &admReviewPass, nil))
	if report.Summary.Pass != 1 {
		t.Errorf("expected Summary.Pass == 1. Got %d", report.Summary.Pass)
	}
	report.AddResult(report.CreateResult(&policy, unstructured.Unstructured{}, &admReviewFail, nil))
	if report.Summary.Fail != 1 {
		t.Errorf("expected Summary.Fail == 1. Got %d", report.Summary.Fail)
	}
	report.AddResult(report.CreateResult(&policy, unstructured.Unstructured{}, &admReviewFail, errors.New("boom")))
	if report.Summary.Error != 1 {
		t.Errorf("expected Summary.Error == 1. Got %d", report.Summary.Error)
	}
}

func TestFindClusterPolicyReportResult(t *testing.T) {
	report := NewClusterPolicyReport("")
	admReviewPass := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{},
		Response: &admv1.AdmissionResponse{
			UID:     "4264aa6a-2d4a-49e6-aed8-156d74678dde",
			Allowed: true,
		},
	}
	policy := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-policy",
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"namespaces"},
					},
				},
				},
			},
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	})

	var expectedResource unstructured.Unstructured
	for i := 0; i < 5; i++ {
		namespaceResource := unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]interface{}{
				"name":              "testingns" + fmt.Sprint(i),
				"creationTimestamp": nil,
			},
			"spec":   map[string]interface{}{},
			"status": map[string]interface{}{},
		},
		}
		report.AddResult(report.CreateResult(&policy, namespaceResource, &admReviewPass, nil))
		expectedResource = namespaceResource
	}

	result := report.GetReusablePolicyReportResult(&policy, expectedResource)
	if result == nil {
		t.Fatal("Result cannot be nil")
	}
	expectedPolicy := "cap-" + policy.GetName()
	if result.Policy != expectedPolicy {
		t.Errorf("Wrong policy. Expected %s, got %s", expectedPolicy, result.Policy)
	}
	expectedObjectReference := &v1.ObjectReference{
		Kind:            expectedResource.GetKind(),
		Namespace:       expectedResource.GetNamespace(),
		Name:            expectedResource.GetName(),
		UID:             expectedResource.GetUID(),
		APIVersion:      expectedResource.GetAPIVersion(),
		ResourceVersion: expectedResource.GetResourceVersion(),
	}
	if !cmp.Equal(result.Subjects[0], expectedObjectReference) {
		diff := cmp.Diff(expectedObjectReference, result.Subjects[0])
		t.Errorf("Result ObjectReference differs from the expected value: %s", diff)
	}
}

func TestFindPolicyReportResult(t *testing.T) {
	namespace := &v1.Namespace{}
	report := NewPolicyReport(namespace)
	admReviewPass := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{},
		Response: &admv1.AdmissionResponse{
			UID:     "4264aa6a-2d4a-49e6-aed8-156d74678dde",
			Allowed: true,
		},
	}
	policy := policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-policy",
		},
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
					},
				},
				},
			},
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	})

	var expectedResource unstructured.Unstructured
	for i := 0; i < 5; i++ {
		namespaceResource := unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":              "testingns" + fmt.Sprint(i),
				"creationTimestamp": nil,
			},
			"spec":   map[string]interface{}{},
			"status": map[string]interface{}{},
		},
		}
		report.AddResult(report.CreateResult(&policy, namespaceResource, &admReviewPass, nil))
		expectedResource = namespaceResource
	}

	result := report.GetReusablePolicyReportResult(&policy, expectedResource)
	if result == nil {
		t.Fatal("Result cannot be nil")
	}
	expectedPolicy := "cap-" + policy.GetName()
	if result.Policy != expectedPolicy {
		t.Errorf("Wrong policy. Expected %s, got %s", expectedPolicy, result.Policy)
	}
	expectedObjectReference := &v1.ObjectReference{
		Kind:            expectedResource.GetKind(),
		Namespace:       expectedResource.GetNamespace(),
		Name:            expectedResource.GetName(),
		UID:             expectedResource.GetUID(),
		APIVersion:      expectedResource.GetAPIVersion(),
		ResourceVersion: expectedResource.GetResourceVersion(),
	}
	if !cmp.Equal(result.Subjects[0], expectedObjectReference) {
		diff := cmp.Diff(expectedObjectReference, result.Subjects[0])
		t.Errorf("Result ObjectReference differs from the expected value: %s", diff)
	}
}

func TestAddPolicyReportResults(t *testing.T) {
	time := metav1.Now()
	timestamp := *time.ProtoTime()
	tests := []struct {
		name          string
		result        *v1alpha2.PolicyReportResult
		expectedPass  int
		expectedFail  int
		expectedError int
	}{
		{"pass", &v1alpha2.PolicyReportResult{
			Source:   PolicyReportSource,
			Policy:   "",           // either cap-policy_name or ap-policy_name
			Rule:     "",           // policy name
			Category: "validating", // either validating, or mutating and validating
			Severity: "info",       // either info for monitor or empty
			// Timestamp shouldn't be used in go structs, and only gives seconds
			// https://github.com/kubernetes/apimachinery/blob/v0.27.2/pkg/apis/meta/v1/time_proto.go#LL48C9-L48C9
			Timestamp:       timestamp,  // time the result was computed
			Result:          StatusPass, // pass, fail, error
			Scored:          false,
			Subjects:        []*v1.ObjectReference{}, // reference to object evaluated
			SubjectSelector: &metav1.LabelSelector{},
			Description:     "", // output message of the policy
			// The policy resource version is used to check if the same result can used
			// in the next scan
			Properties: map[string]string{PropertyPolicyResourceVersion: "", PropertyPolicyUID: ""},
		}, 1, 0, 0},
		{"fail", &v1alpha2.PolicyReportResult{
			Source:   PolicyReportSource,
			Policy:   "",           // either cap-policy_name or ap-policy_name
			Rule:     "",           // policy name
			Category: "validating", // either validating, or mutating and validating
			Severity: "info",       // either info for monitor or empty
			// Timestamp shouldn't be used in go structs, and only gives seconds
			// https://github.com/kubernetes/apimachinery/blob/v0.27.2/pkg/apis/meta/v1/time_proto.go#LL48C9-L48C9
			Timestamp:       timestamp,  // time the result was computed
			Result:          StatusFail, // pass, fail, error
			Scored:          false,
			Subjects:        []*v1.ObjectReference{}, // reference to object evaluated
			SubjectSelector: &metav1.LabelSelector{},
			Description:     "", // output message of the policy
			// The policy resource version is used to check if the same result can used
			// in the next scan
			Properties: map[string]string{PropertyPolicyResourceVersion: "", PropertyPolicyUID: ""},
		}, 0, 1, 0},
		{"error", &v1alpha2.PolicyReportResult{
			Source:   PolicyReportSource,
			Policy:   "",           // either cap-policy_name or ap-policy_name
			Rule:     "",           // policy name
			Category: "validating", // either validating, or mutating and validating
			Severity: "info",       // either info for monitor or empty
			// Timestamp shouldn't be used in go structs, and only gives seconds
			// https://github.com/kubernetes/apimachinery/blob/v0.27.2/pkg/apis/meta/v1/time_proto.go#LL48C9-L48C9
			Timestamp:       timestamp,   // time the result was computed
			Result:          StatusError, // pass, fail, error
			Scored:          false,
			Subjects:        []*v1.ObjectReference{}, // reference to object evaluated
			SubjectSelector: &metav1.LabelSelector{},
			Description:     "", // output message of the policy
			// The policy resource version is used to check if the same result can used
			// in the next scan
			Properties: map[string]string{PropertyPolicyResourceVersion: "", PropertyPolicyUID: ""},
		}, 0, 0, 1},
	}
	for _, ttest := range tests {
		t.Run(ttest.name, func(t *testing.T) {
			clusterReport := NewClusterPolicyReport("")
			namespace := &v1.Namespace{}
			nsReport := NewPolicyReport(namespace)

			clusterReport.AddResult(ttest.result)
			nsReport.AddResult(ttest.result)

			if clusterReport.Summary.Pass != ttest.expectedPass {
				t.Errorf("Invalid cluster report summary. Expected pass evaluations count to be %d. But got %d", ttest.expectedPass, clusterReport.Summary.Pass)
			}
			if clusterReport.Summary.Fail != ttest.expectedFail {
				t.Errorf("Invalid cluster report summary. Expected fail evaluations count to be %d. But got %d", ttest.expectedFail, clusterReport.Summary.Fail)
			}
			if clusterReport.Summary.Error != ttest.expectedError {
				t.Errorf("Invalid cluster report summary. Expected error evaluations count to be %d. But got %d", ttest.expectedError, clusterReport.Summary.Error)
			}
			if nsReport.Summary.Pass != ttest.expectedPass {
				t.Errorf("Invalid namespaced report summary. Expected pass evaluations count to be %d. But got %d", ttest.expectedPass, nsReport.Summary.Pass)
			}
			if nsReport.Summary.Fail != ttest.expectedFail {
				t.Errorf("Invalid namespaced report summary. Expected fail evaluations count to be %d. But got %d", ttest.expectedFail, nsReport.Summary.Fail)
			}
			if nsReport.Summary.Error != ttest.expectedError {
				t.Errorf("Invalid namespaced report summary. Expected error evaluations count to be %d. But got %d", ttest.expectedError, nsReport.Summary.Error)
			}
		})
	}
}
