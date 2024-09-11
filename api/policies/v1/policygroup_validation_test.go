package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidatePolicyGroupExpressionField(t *testing.T) {
	tests := []struct {
		name                 string
		policy               Policy
		expectedErrorMessage string
	}{
		{
			"with valid expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					PolicyGroupSpec: PolicyGroupSpec{
						Expression: "policy1() && policy2()",
						Message:    "This is a test policy",
						Policies: PolicyGroupMembers{
							"policy1": {
								Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
							},
							"policy2": {
								Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
							},
						},
					},
				},
			},
			"",
		},
		{
			"with empty expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					PolicyGroupSpec: PolicyGroupSpec{
						Expression: "",
						Message:    "This is a test policy",
						Policies: PolicyGroupMembers{
							"policy1": {
								Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
							},
							"policy2": {
								Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
							},
						},
					},
				},
			},
			`spec.expression: Required value: must be non-empty`,
		},
		{
			"with non-boolean expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					PolicyGroupSpec: PolicyGroupSpec{
						Expression: "123",
						Message:    "This is a test policy",
						Policies: PolicyGroupMembers{
							"policy1": {
								Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
							},
							"policy2": {
								Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
							},
						},
					},
				},
			},
			`spec.expression: Invalid value: "123": must evaluate to bool`,
		},
		{
			"with invalid expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					PolicyGroupSpec: PolicyGroupSpec{
						Expression: "2 > 1",
						Message:    "This is a test policy",
						Policies: PolicyGroupMembers{
							"policy1": {
								Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
							},
							"policy2": {
								Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
							},
						},
					},
				},
			},
			`spec.expression: Invalid value: "2 > 1": compilation failed`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyGroupExpressionField(test.policy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidatePolicyGroupMembers(t *testing.T) {
	tests := []struct {
		name                 string
		policy               Policy
		expectedErrorMessage string
	}{
		{
			"with valid policy members",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					PolicyGroupSpec: PolicyGroupSpec{
						Expression: "policy1() && policy2()",
						Message:    "This is a test policy",
						Policies: PolicyGroupMembers{
							"policy1": {
								Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
							},
							"policy2": {
								Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
							},
						},
					},
				},
			},
			"",
		},
		{
			"with no policy members",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					PolicyGroupSpec: PolicyGroupSpec{
						Policies: map[string]PolicyGroupMember{},
					},
				},
			},
			`spec.policies: Required value: policy groups must have at least one policy member`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyGroupMembers(test.policy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
