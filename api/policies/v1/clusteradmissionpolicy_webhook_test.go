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
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

func TestClusterAdmissionPolicyDefault(t *testing.T) {
	defaulter := clusterAdmissionPolicyDefaulter{logger: logr.Discard()}
	policy := &ClusterAdmissionPolicy{}

	err := defaulter.Default(context.Background(), policy)
	require.NoError(t, err)

	assert.Equal(t, constants.DefaultPolicyServer, policy.GetPolicyServer())
	assert.Contains(t, policy.GetFinalizers(), constants.KubewardenFinalizer)
}

func TestClusterAdmissionPolicyValidateCreate(t *testing.T) {
	validator := clusterAdmissionPolicyValidator{logger: logr.Discard()}
	policy := NewClusterAdmissionPolicyFactory().Build()

	warnings, err := validator.ValidateCreate(context.Background(), policy)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestClusterAdmissionPolicyValidateCreateWithErrors(t *testing.T) {
	policy := NewClusterAdmissionPolicyFactory().
		WithPolicyServer("").
		WithRules([]admissionregistrationv1.RuleWithOperations{
			{},
			{
				Operations: []admissionregistrationv1.OperationType{},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
				},
			},
			{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
				},
			},
			{
				Operations: []admissionregistrationv1.OperationType{""},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
				},
			},
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{},
					Resources:   []string{"*/*"},
				},
			},
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{},
				},
			},
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{""},
					Resources:   []string{"*/*"},
				},
			},
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{""},
				},
			},
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"", "pods"},
				},
			},
		}).
		WithMatchConditions([]admissionregistrationv1.MatchCondition{
			{
				Name:       "foo",
				Expression: "1 + 1",
			},
			{
				Name:       "foo",
				Expression: "invalid expression",
			},
		}).
		Build()

	validator := clusterAdmissionPolicyValidator{logger: logr.Discard()}

	warnings, err := validator.ValidateCreate(context.Background(), policy)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestClusterAdmissionPolicyValidateUpdate(t *testing.T) {
	validator := clusterAdmissionPolicyValidator{logger: logr.Discard()}
	oldPolicy := NewClusterAdmissionPolicyFactory().Build()
	newPolicy := NewClusterAdmissionPolicyFactory().Build()

	warnings, err := validator.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	oldPolicy = NewClusterAdmissionPolicyFactory().
		WithMode("monitor").
		Build()
	newPolicy = NewClusterAdmissionPolicyFactory().
		WithMode("protect").
		Build()

	warnings, err = validator.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestClusterAdmissionPolicyValidateUpdateWithErrors(t *testing.T) {
	validator := clusterAdmissionPolicyValidator{logger: logr.Discard()}
	oldPolicy := NewClusterAdmissionPolicyFactory().
		WithPolicyServer("old").
		Build()
	newPolicy := NewClusterAdmissionPolicyFactory().
		WithPolicyServer("new").
		Build()

	warnings, err := validator.ValidateUpdate(context.Background(), newPolicy, oldPolicy)
	require.Error(t, err)
	assert.Empty(t, warnings)

	newPolicy = NewClusterAdmissionPolicyFactory().
		WithPolicyServer("new").
		WithMode("monitor").
		Build()

	warnings, err = validator.ValidateUpdate(context.Background(), newPolicy, oldPolicy)
	require.Error(t, err)
	assert.Empty(t, warnings)
}
