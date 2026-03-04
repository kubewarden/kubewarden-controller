package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
)

const testDeploymentsNamespace = "kubewarden"

// expectedExcludeExpr is the LabelSelectorRequirement that must be present
// in the NamespaceSelector to exclude the deployments namespace.
var expectedExcludeExpr = metav1.LabelSelectorRequirement{
	Key:      "kubernetes.io/metadata.name",
	Operator: metav1.LabelSelectorOpNotIn,
	Values:   []string{testDeploymentsNamespace},
}

func TestNamespaceSelectorClusterAdmissionTypePolicies(t *testing.T) {
	tests := []struct {
		name                                    string
		allowInsideAdmissionControllerNamespace bool
		policyNSSel                             *metav1.LabelSelector
		expected                                *metav1.LabelSelector
	}{
		{
			name:                                    "adds NotIn expression when allowInsideAdmissionControllerNamespace is false and policy has no NamespaceSelector",
			allowInsideAdmissionControllerNamespace: false,
			policyNSSel:                             nil,
			expected: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					expectedExcludeExpr,
				},
			},
		},
		{
			name:                                    "merges existing MatchExpressions with the NotIn expression when allowInsideAdmissionControllerNamespace is false",
			allowInsideAdmissionControllerNamespace: false,
			policyNSSel: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
			expected: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					expectedExcludeExpr,
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
		},
		{
			name:                                    "returns the policy NamespaceSelector unchanged when allowInsideAdmissionControllerNamespace is true",
			allowInsideAdmissionControllerNamespace: true,
			policyNSSel: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
			expected: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
		{
			name:                                    "returns nil when allowInsideAdmissionControllerNamespace is true and policy has no NamespaceSelector",
			allowInsideAdmissionControllerNamespace: true,
			policyNSSel:                             nil,
			expected:                                nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &policySubReconciler{
				deploymentsNamespace: testDeploymentsNamespace,
			}
			policy := policiesv1.NewClusterAdmissionPolicyFactory().Build()
			policy.Spec.NamespaceSelector = tc.policyNSSel
			policy.Spec.AllowInsideAdmissionControllerNamespace = tc.allowInsideAdmissionControllerNamespace

			got := r.namespaceSelector(policy)
			require.Equal(t, tc.expected, got)

			policyGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().Build()
			policyGroup.Spec.NamespaceSelector = tc.policyNSSel
			policyGroup.Spec.AllowInsideAdmissionControllerNamespace = tc.allowInsideAdmissionControllerNamespace

			got = r.namespaceSelector(policyGroup)
			require.Equal(t, tc.expected, got)
		})
	}
}
