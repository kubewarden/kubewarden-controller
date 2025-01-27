/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestSensitiveResourceMatchRule(t *testing.T) {
	sr := sensitiveResource{
		APIGroup: "apps",
		Resource: "deployments",
	}

	tests := []struct {
		name      string
		apiGroups []string
		resources []string
		matches   bool
	}{
		{
			"with matching APIGroups and Resources",
			[]string{"apps"},
			[]string{"statefulsets", "deployments"},
			true,
		},
		{
			"with APIGroups using wildcard and matching Resources",
			[]string{"*"},
			[]string{"deployments"},
			true,
		},
		{
			"with Resources using wildcards and APIGroups matching",
			[]string{"apps"},
			[]string{"*"},
			true,
		},
		{
			"with Resources using double wildcards and APIGroups matching",
			[]string{"apps"},
			[]string{"*/*"},
			true,
		},
		{
			"with sub-Resources using wildcards and APIGroups matching",
			[]string{"apps"},
			[]string{"deployments/*"},
			true,
		},
		{
			"with sub-Resources and APIGroups matching",
			[]string{"apps"},
			[]string{"deployments/status"},
			true,
		},
		{
			"with only APIGroups matching",
			[]string{"apps"},
			[]string{"statefulsets"},
			false,
		},
		{
			"with APIGroups not matching and a Resopurce using wildcard",
			[]string{""},
			[]string{"*"},
			false,
		},
		{
			"with APIGroups not matching and a Resopurce matching",
			[]string{"argoproj.io"},
			[]string{"deployments"},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.matches, sr.MatchesRules(test.apiGroups, test.resources))
		})
	}
}

func TestValidateRulesField(t *testing.T) {
	tests := []struct {
		name                  string
		policy                Policy
		expectedErrorMessages []string // use nil when no error is expected
	}{
		{
			"with valid APIVersion and resources. But with empty APIGroup",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}).
				WithPolicyServer("default").Build(),
			nil,
		},
		{
			"with valid APIVersion, Resources and APIGroup",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"deployments"},
						},
					},
				}).
				WithPolicyServer("default").Build(),
			nil,
		},
		{
			"with no operations and API groups and resources",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules: Required value: a value must be specified"},
		},
		{
			"with empty objects",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules.operations: Required value: a value must be specified"},
		},
		{
			"with no operations",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules.operations: Required value: a value must be specified"},
		},
		{
			"with null operations",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: nil,
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{"*/*"},
					},
				}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules.operations: Required value: a value must be specified"},
		},
		{
			"with empty operations string",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{""},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{"*/*"},
					},
				}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules.operations[0]: Required value: must be non-empty"},
		},
		{
			"with no apiVersion",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{},
						Resources:   []string{"*/*"},
					},
				}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules: Required value: apiVersions and resources must have specified values"},
		},
		{
			"with no resources",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules: Required value: apiVersions and resources must have specified values"},
		},
		{
			"with empty apiVersion string",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{""},
						Resources:   []string{"*/*"},
					},
				}}).WithPolicyServer("defaule").Build(),
			[]string{"spec.rules.rule.apiVersions[0]: Required value: must be non-empty"},
		},
		{
			"with empty resources string",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{""},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules.rule.resources[0]: Required value: must be non-empty"},
		},
		{
			"with some of the resources are empty strings",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"", "pods"},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules.rule.resources[0]: Required value: must be non-empty"},
		},
		{
			"with all operations and API groups and resources",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"with wildcard usage. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules.apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules.resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"with wildcard usage. But an AdmissionPolicyGroup",
			NewAdmissionPolicyGroupFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules.apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules.resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"targeting a PolicyReport. But a ClusterAdmissionPolicy",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"wgpolicyk8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"policyreports"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"targeting a PolicyReport. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"wgpolicyk8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"policyreports"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules: Forbidden: {APIGroup: wgpolicyk8s.io, Resource: policyreports} resources cannot be targeted by AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"targeting a wgpolicyk8s.io resources. But an AdmissionPolicyGroup",
			NewAdmissionPolicyGroupFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"wgpolicyk8s.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules: Forbidden: {APIGroup: wgpolicyk8s.io, Resource: policyreports} resources cannot be targeted by AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allErrors := validateRulesField(test.policy)

			if len(test.expectedErrorMessages) != 0 {
				err := prepareInvalidAPIError(test.policy, allErrors)
				for _, expectedErrorMessage := range test.expectedErrorMessages {
					require.ErrorContains(t, err, expectedErrorMessage)
				}
			} else {
				require.Empty(t, allErrors)
			}
		})
	}
}

func TestValidateMatchConditionsField(t *testing.T) {
	defaultRules := []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
			Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
		},
	}
	tests := []struct {
		name                 string
		policy               Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"with empty MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				Build(),
			"",
		},
		{
			"with valid MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions([]admissionregistrationv1.MatchCondition{
					{
						Name:       "foo",
						Expression: "true",
					},
				}).
				WithPolicyServer("default").
				Build(),
			"",
		},
		{
			"with non-boolean MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions([]admissionregistrationv1.MatchCondition{
					{
						Name:       "foo",
						Expression: "1 + 1",
					},
				}).
				WithPolicyServer("default").
				Build(),
			"Invalid value: \"1 + 1\": must evaluate to bool",
		},
		{
			"with invalid expression in MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions([]admissionregistrationv1.MatchCondition{
					{
						Name:       "foo",
						Expression: "invalid expression",
					},
				}).
				WithPolicyServer("default").
				Build(),
			"Syntax error: extraneous input 'expression'",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allErrors := validateMatchConditions(test.policy.GetMatchConditions(), field.NewPath("spec").Child("matchConditions"))

			if test.expectedErrorMessage != "" {
				err := prepareInvalidAPIError(test.policy, allErrors)
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Empty(t, allErrors)
			}
		})
	}
}

func TestValidatePolicyServerField(t *testing.T) {
	defaultRules := []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		},
	}}
	tests := []struct {
		name                 string
		oldPolicy            Policy
		newPolicy            Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"policy server unchanged",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("old-policy-server").
				WithMode("monitor").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("old-policy-server").
				WithMode("monitor").
				Build(),
			"",
		},
		{
			"policy server changed",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("old-policy-server").
				WithMode("monitor").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("new-policy-server").
				WithMode("monitor").
				Build(),
			"spec.policyServer: Forbidden: the field is immutable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyServerField(test.oldPolicy, test.newPolicy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidatePolicyModeField(t *testing.T) {
	defaultRules := []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		},
	}}
	tests := []struct {
		name                 string
		oldPolicy            Policy
		newPolicy            Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"policy mode unchanged",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			"",
		},
		{
			"policy mode changed from monitor to protect",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("monitor").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			"",
		},
		{
			"policy mode changed from protect to monitor",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("monitor").
				Build(),
			"spec.mode: Forbidden: field cannot transition from protect to monitor. Recreate instead.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyModeField(test.oldPolicy, test.newPolicy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
