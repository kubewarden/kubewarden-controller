package report

import (
	"errors"
	"testing"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestAddResult(t *testing.T) {
	report := NewClusterPolicyReport("clusterwide")
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

	report.AddResult(&policy, unstructured.Unstructured{}, &admReviewPass, nil)
	if report.Summary.Pass != 1 {
		t.Errorf("expected Summary.Pass == 1")
	}
	report.AddResult(&policy, unstructured.Unstructured{}, &admReviewFail, nil)
	if report.Summary.Fail != 1 {
		t.Errorf("expected Summary.Fail == 1")
	}
	report.AddResult(&policy, unstructured.Unstructured{}, &admReviewFail, errors.New("boom"))
	if report.Summary.Error != 1 {
		t.Errorf("expected Summary.Error == 1")
	}
}
