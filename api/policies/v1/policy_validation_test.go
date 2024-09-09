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
)

func TestValidateRulesField(t *testing.T) {
	tests := []struct {
		name                 string
		policy               Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"with valid APIVersion and resources. But with empty APIGroup", clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"pods"},
				},
			}}, nil, "default", "protect"),
			"",
		},
		{
			"with valid APIVersion, Resources and APIGroup",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "default", "protect"),
			"",
		},
		{
			"with no operations and API groups and resources",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{}, nil, "default", "protect"),
			"spec.rules: Required value: a value must be specified",
		},
		{
			"with empty objects",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{}}, nil, "default", "protect"),
			"spec.rules.operations: Required value: a value must be specified",
		},
		{
			"with no operations",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
				},
			}}, nil, "default", "protect"),
			"spec.rules.operations: Required value: a value must be specified",
		},
		{
			"with null operations",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
				},
			}}, nil, "default", "protect"),
			"spec.rules.operations: Required value: a value must be specified",
		},
		{
			"with empty operations string",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{""},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
				},
			}}, nil, "default", "protect"),
			"spec.rules.operations[0]: Required value: must be non-empty",
		},
		{
			"with no apiVersion",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{},
					Resources:   []string{"*/*"},
				},
			}}, nil, "default", "protect"),
			"spec.rules: Required value: apiVersions and resources must have specified values",
		},
		{
			"with no resources",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{},
				},
			}}, nil, "default", "protect"),
			"spec.rules: Required value: apiVersions and resources must have specified values",
		},
		{
			"with empty apiVersion string",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{""},
					Resources:   []string{"*/*"},
				},
			}}, nil, "default", "protect"),
			"spec.rules.rule.apiVersions[0]: Required value: must be non-empty",
		},
		{
			"with empty resources string",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{""},
				},
			}}, nil, "default", "protect"),
			"spec.rules.rule.resources[0]: Required value: must be non-empty",
		},
		{
			"with some of the resources are empty strings",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"", "pods"},
				},
			}}, nil, "default", "protect"),
			"spec.rules.rule.resources[0]: Required value: must be non-empty",
		},
		{
			"with all operations and API groups and resources",
			clusterAdmissionPolicyFactory(nil, nil, "default", "protect"),
			"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allErrors := validateRulesField(test.policy)

			if test.expectedErrorMessage != "" {
				err := prepareInvalidAPIError(test.policy, allErrors)
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Empty(t, allErrors)
			}
		})
	}
}

func TestValidateMatchConditionsField(t *testing.T) {
	tests := []struct {
		name                 string
		policy               Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"with empty MatchConditions",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
			}}, nil, "default", "protect"),
			"",
		},
		{
			"with valid MatchConditions",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
			}}, []admissionregistrationv1.MatchCondition{
				{
					Name:       "foo",
					Expression: "true",
				},
			}, "default", "protect"),
			"",
		},
		{
			"with non-boolean MatchConditions",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
			}}, []admissionregistrationv1.MatchCondition{
				{
					Name:       "foo",
					Expression: "1 + 1",
				},
			}, "default", "protect"),
			"Invalid value: \"1 + 1\": must evaluate to bool",
		},
		{
			"with invalid expression in MatchConditions",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
			}}, []admissionregistrationv1.MatchCondition{
				{
					Name:       "foo",
					Expression: "invalid expression",
				},
			}, "default", "protect"), "Syntax error: extraneous input 'expression'",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allErrors := validateMatchConditionsField(test.policy)

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
	tests := []struct {
		name                 string
		oldPolicy            Policy
		newPolicy            Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"policy server unchanged",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "old-policy-server", "monitor"),
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "old-policy-server", "monitor"),
			"",
		},
		{
			"policy server changed",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "old-policy-server", "monitor"),
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "new-policy-server", "monitor"),
			"spec.policyServer: Forbidden: the field is immutable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyServerField(test.newPolicy, test.oldPolicy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidatePolicyModeField(t *testing.T) {
	tests := []struct {
		name                 string
		oldPolicy            Policy
		newPolicy            Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"policy mode unchanged",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "default", "protect"),
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "default", "protect"),
			"",
		},
		{
			"policy mode changed from protect to monitor",
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "default", "protect"),
			clusterAdmissionPolicyFactory([]admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			}}, nil, "default", "monitor"),
			"spec.mode: Forbidden: field cannot transition from protect to monitor. Recreate instead.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyModeField(test.newPolicy, test.oldPolicy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
