package v1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidatePolicyGroupExpressionField(t *testing.T) {
	tests := []struct {
		name                 string
		policyGroup          PolicyGroup
		expectedErrorMessage string
	}{
		{
			"with valid expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "policy1() && policy2()",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
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
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
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
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "123",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
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
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "2 > 1",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
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
			err := validatePolicyGroupExpressionField(test.policyGroup)

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
		policyGroup          PolicyGroup
		expectedErrorMessage string
	}{
		{
			"with valid policy members",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "policy1() && policy2()",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
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
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: map[string]PolicyGroupMemberWithContext{},
					},
				},
			},
			`spec.policies: Required value: policy groups must have at least one policy member`,
		},
		{
			"policy member with empty name",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "": policy group member name is invalid`,
		},
		{
			"policy member with reserved keyword",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"in": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "in": policy group member name is invalid`,
		},
		{
			"policy member name cannot start with digits",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"0policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "0policy1": policy group member name is invalid`,
		},
		{
			"policy member name cannot have special chars",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"p!ol.ic?y1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "p!ol.ic?y1": policy group member name is invalid`,
		},
		{
			"policy member names allow underscores",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"_policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"pol_icy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			"",
		},
		{
			"policy member names allow digits in the middle",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"po0licy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy21": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errors := validatePolicyGroupMembers(test.policyGroup)

			if test.expectedErrorMessage != "" {
				errors = errors.Filter(func(e error) bool {
					return !strings.Contains(e.Error(), test.expectedErrorMessage)
				})
				require.NotEmpty(t, errors)
			} else {
				require.Empty(t, errors)
			}
		})
	}
}
