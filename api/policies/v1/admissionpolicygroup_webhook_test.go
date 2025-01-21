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
	corev1 "k8s.io/api/core/v1"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

func TestAdmissionPolicyGroupDefault(t *testing.T) {
	defaulter := admissionPolicyGroupDefaulter{logger: logr.Discard()}
	policy := &AdmissionPolicyGroup{}

	err := defaulter.Default(context.Background(), policy)
	require.NoError(t, err)

	assert.Equal(t, constants.DefaultPolicyServer, policy.GetPolicyServer())
	assert.Contains(t, policy.GetFinalizers(), constants.KubewardenFinalizer)
}

func TestAdmissionPolicyGroupDefaultWithInvalidType(t *testing.T) {
	defaulter := admissionPolicyGroupDefaulter{logger: logr.Discard()}
	obj := &corev1.Pod{}

	err := defaulter.Default(context.Background(), obj)
	require.ErrorContains(t, err, "expected an AdmissionPolicyGroup object, got *v1.Pod")
}

func TestAdmissionPolicyGroupValidateCreate(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	policy := NewAdmissionPolicyGroupFactory().Build()

	warnings, err := validator.ValidateCreate(context.Background(), policy)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateCreateWithErrors(t *testing.T) {
	policy := NewAdmissionPolicyGroupFactory().
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

	validator := admissionPolicyGroupValidator{}

	warnings, err := validator.ValidateCreate(context.Background(), policy)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateCreateWithInvalidType(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	obj := &corev1.Pod{}

	warnings, err := validator.ValidateCreate(context.Background(), obj)
	require.ErrorContains(t, err, "expected an AdmissionPolicyGroup object, got *v1.Pod")
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateUpdate(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	oldPolicy := NewAdmissionPolicyGroupFactory().Build()
	newPolicy := NewAdmissionPolicyGroupFactory().Build()

	warnings, err := validator.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	require.NoError(t, err)
	assert.Empty(t, warnings)

	oldPolicy = NewAdmissionPolicyGroupFactory().
		WithMode("monitor").
		Build()
	newPolicy = NewAdmissionPolicyGroupFactory().
		WithMode("protect").
		Build()

	warnings, err = validator.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateUpdateWithErrors(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	oldPolicy := NewAdmissionPolicyGroupFactory().
		WithPolicyServer("old").
		Build()
	newPolicy := NewAdmissionPolicyGroupFactory().
		WithPolicyServer("new").
		Build()

	warnings, err := validator.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	require.Error(t, err)
	assert.Empty(t, warnings)

	newPolicy = NewAdmissionPolicyGroupFactory().
		WithPolicyServer("new").
		WithMode("monitor").
		Build()

	warnings, err = validator.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateUpdateWithInvalidType(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	obj := &corev1.Pod{}
	oldPolicy := NewAdmissionPolicyGroupFactory().Build()
	newPolicy := NewAdmissionPolicyGroupFactory().Build()

	warnings, err := validator.ValidateUpdate(context.Background(), obj, newPolicy)
	require.ErrorContains(t, err, "expected an AdmissionPolicyGroup object, got *v1.Pod")
	assert.Empty(t, warnings)

	warnings, err = validator.ValidateUpdate(context.Background(), oldPolicy, obj)
	require.ErrorContains(t, err, "expected an AdmissionPolicyGroup object, got *v1.Pod")
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateDelete(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	policy := NewAdmissionPolicyGroupFactory().Build()

	warnings, err := validator.ValidateDelete(context.Background(), policy)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestAdmissionPolicyGroupValidateDeleteWithInvalidType(t *testing.T) {
	validator := admissionPolicyGroupValidator{logger: logr.Discard()}
	obj := &corev1.Pod{}

	warnings, err := validator.ValidateDelete(context.Background(), obj)
	require.ErrorContains(t, err, "expected an AdmissionPolicyGroup object, got *v1.Pod")
	assert.Empty(t, warnings)
}
