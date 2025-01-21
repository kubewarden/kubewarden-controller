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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

func TestPolicyServerDefault(t *testing.T) {
	defaulter := policyServerDefaulter{}
	policyServer := &PolicyServer{}

	err := defaulter.Default(context.Background(), policyServer)
	require.NoError(t, err)

	assert.Contains(t, policyServer.Finalizers, constants.KubewardenFinalizer)
}

func TestPolicyServerDefaultWithInvalidType(t *testing.T) {
	policyServerDefaulter := policyServerDefaulter{}
	obj := &corev1.Pod{}

	err := policyServerDefaulter.Default(context.Background(), obj)
	require.ErrorContains(t, err, "expected a PolicyServer object, got *v1.Pod")
}

func TestPolicyServerValidateCreate(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	policyServer := NewPolicyServerFactory().Build()

	warnings, err := validator.ValidateCreate(context.Background(), policyServer)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateCreateWithErrors(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	policyServer := NewPolicyServerFactory().
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		WithMinAvailable(ptr.To(intstr.FromInt(2))).
		Build()

	warnings, err := validator.ValidateCreate(context.Background(), policyServer)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateCreateWithInvalidType(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	obj := &corev1.Pod{}

	warnings, err := validator.ValidateCreate(context.Background(), obj)
	require.ErrorContains(t, err, "expected a PolicyServer object, got *v1.Pod")
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateUpdate(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	oldPolicyServer := NewPolicyServerFactory().Build()
	newPolicyServer := NewPolicyServerFactory().
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		Build()

	warnings, err := validator.ValidateUpdate(context.Background(), oldPolicyServer, newPolicyServer)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateUpdateWithErrors(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	oldPolicyServer := NewPolicyServerFactory().Build()
	newPolicyServer := NewPolicyServerFactory().
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		WithMinAvailable(ptr.To(intstr.FromInt(2))).
		Build()

	warnings, err := validator.ValidateUpdate(context.Background(), oldPolicyServer, newPolicyServer)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateUpdateWithInvalidType(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	obj := &corev1.Pod{}
	newPolicyServer := NewPolicyServerFactory().Build()

	warnings, err := validator.ValidateUpdate(context.Background(), newPolicyServer, obj)
	require.ErrorContains(t, err, "expected a PolicyServer object, got *v1.Pod")
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateName(t *testing.T) {
	name := make([]byte, 64)
	for i := range name {
		name[i] = 'a'
	}
	policyServer := NewPolicyServerFactory().WithName(string(name)).Build()

	policyServerValidator := policyServerValidator{logger: logr.Discard()}
	err := policyServerValidator.validate(context.Background(), policyServer)
	require.ErrorContains(t, err, "the PolicyServer name cannot be longer than 63 characters")
}

func TestPolicyServerValidateMinAvailableMaxUnavailable(t *testing.T) {
	policyServer := NewPolicyServerFactory().
		WithMinAvailable(ptr.To(intstr.FromInt(2))).
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		Build()

	policyServerValidator := policyServerValidator{logger: logr.Discard()}

	err := policyServerValidator.validate(context.Background(), policyServer)
	require.ErrorContains(t, err, "minAvailable and maxUnavailable cannot be both set")
}

func TestPolicyServerValidateImagePullSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		valid  bool
	}{
		{
			"non existing secret",
			nil,
			false,
		},
		{
			"secret of wrong type",
			&corev1.Secret{
				Type: "Opaque",
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			},
			false,
		},
		{
			"valid secret",
			&corev1.Secret{
				Type: "kubernetes.io/dockerconfigjson",
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
			},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().Build()

			if test.secret != nil {
				err := k8sClient.Create(context.Background(), test.secret)
				if err != nil {
					t.Errorf("failed to create secret: %s", err.Error())
				}
			}

			policyServer := NewPolicyServerFactory().
				WithImagePullSecret("test").
				Build()

			policyServerValidator := policyServerValidator{
				deploymentsNamespace: "default",
				k8sClient:            k8sClient,
				logger:               logr.Discard(),
			}
			err := policyServerValidator.validate(context.Background(), policyServer)

			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestPolicyServerValidateLimitsAndRequests(t *testing.T) {
	tests := []struct {
		name     string
		limits   corev1.ResourceList
		requests corev1.ResourceList
		error    string
	}{
		{
			name:     "valid",
			limits:   corev1.ResourceList{"cpu": resource.MustParse("100m")},
			requests: corev1.ResourceList{"cpu": resource.MustParse("50m")},
			error:    "",
		},
		{
			name:     "negative limit",
			limits:   corev1.ResourceList{"cpu": resource.MustParse("-100m")},
			requests: corev1.ResourceList{"cpu": resource.MustParse("100m")},
			error:    `spec.limits.cpu: Invalid value: "-100m": must be greater than or equal to 0`,
		},
		{
			name:     "negative request",
			limits:   corev1.ResourceList{"cpu": resource.MustParse("100m")},
			requests: corev1.ResourceList{"cpu": resource.MustParse("-100m")},
			error:    `spec.requests.cpu: Invalid value: "-100m": must be greater than or equal to 0`,
		},
		{
			name:     "request greater than limit",
			limits:   corev1.ResourceList{"cpu": resource.MustParse("100m")},
			requests: corev1.ResourceList{"cpu": resource.MustParse("200m")},
			error:    `spec.requests.cpu: Invalid value: "200m": must be less than or equal to cpu limit of 100m`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyServer := NewPolicyServerFactory().
				WithLimits(test.limits).
				WithRequests(test.requests).
				Build()

			policyServerValidator := policyServerValidator{logger: logr.Discard()}
			err := policyServerValidator.validate(context.Background(), policyServer)

			if test.error != "" {
				require.ErrorContains(t, err, test.error)
			}
		})
	}
}
