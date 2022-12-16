package policies

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestFilterAuditablePolicies(t *testing.T) {
	noBackgroundAudit := policiesv1.ClusterAdmissionPolicy{Spec: policiesv1.ClusterAdmissionPolicySpec{
		PolicySpec: policiesv1.PolicySpec{BackgroundAudit: false},
	}}
	pending := policiesv1.AdmissionPolicy{
		Spec:   policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{BackgroundAudit: true}},
		Status: policiesv1.PolicyStatus{PolicyStatus: policiesv1.PolicyStatusPending},
	}
	noCreate := policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{"DELETE"},
					Rule:       admissionregistrationv1.Rule{},
				}},
			},
		},
		Status: policiesv1.PolicyStatus{PolicyStatus: policiesv1.PolicyStatusActive},
	}
	hasAllResources := policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{"CREATE"},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   nil,
						APIVersions: nil,
						Resources:   []string{"*"},
						Scope:       nil,
					},
				}},
			},
		},
		Status: policiesv1.PolicyStatus{PolicyStatus: policiesv1.PolicyStatusActive},
	}
	auditable := policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{"CREATE"},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   nil,
						APIVersions: nil,
						Resources:   []string{"pods"},
						Scope:       nil,
					},
				}},
			},
		},
		Status: policiesv1.PolicyStatus{PolicyStatus: policiesv1.PolicyStatusActive},
	}

	tests := []struct {
		name     string
		policies []policiesv1.Policy
		expect   []policiesv1.Policy
	}{
		{"policy without background audit", []policiesv1.Policy{&noBackgroundAudit}, []policiesv1.Policy{}},
		{"policy not active", []policiesv1.Policy{&pending}, []policiesv1.Policy{}},
		{"policy without create operation", []policiesv1.Policy{&noCreate}, []policiesv1.Policy{}},
		{"policy with all resources (*)", []policiesv1.Policy{&hasAllResources}, []policiesv1.Policy{}},
		{"auditable policy", []policiesv1.Policy{&auditable}, []policiesv1.Policy{&auditable}},
		{"auditable policy with all the others policies", []policiesv1.Policy{&auditable, &noBackgroundAudit, &noCreate, &pending, &hasAllResources}, []policiesv1.Policy{&auditable}},
		{"empty array", []policiesv1.Policy{}, []policiesv1.Policy{}},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			policies := filterAuditablePolicies(ttest.policies)
			if !cmp.Equal(policies, ttest.expect) {
				t.Errorf("expected %v, but got %v", ttest.expect, policies)
			}
		})
	}
}
