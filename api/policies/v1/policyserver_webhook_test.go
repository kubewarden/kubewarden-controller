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

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/kubewarden/adm-controller/internal/constants"
)

const fakeSigstoreTrustConfig = `{"trusted_root": {"version": "test"}}`

func TestPolicyServerDefault(t *testing.T) {
	defaulter := policyServerDefaulter{}
	policyServer := &PolicyServer{}

	err := defaulter.Default(t.Context(), policyServer)
	require.NoError(t, err)

	assert.Contains(t, policyServer.Finalizers, constants.KubewardenFinalizer)
}

func TestPolicyServerValidateCreate(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	policyServer := NewPolicyServerFactory().Build()

	warnings, err := validator.ValidateCreate(t.Context(), policyServer)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateCreateWithErrors(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	policyServer := NewPolicyServerFactory().
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		WithMinAvailable(ptr.To(intstr.FromInt(2))).
		Build()

	warnings, err := validator.ValidateCreate(t.Context(), policyServer)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateUpdate(t *testing.T) {
	validator := policyServerValidator{logger: logr.Discard()}
	oldPolicyServer := NewPolicyServerFactory().Build()
	newPolicyServer := NewPolicyServerFactory().
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		Build()

	warnings, err := validator.ValidateUpdate(t.Context(), oldPolicyServer, newPolicyServer)
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

	warnings, err := validator.ValidateUpdate(t.Context(), oldPolicyServer, newPolicyServer)
	require.Error(t, err)
	assert.Empty(t, warnings)
}

func TestPolicyServerValidateName(t *testing.T) {
	name := make([]byte, 64)
	for i := range name {
		name[i] = 'a'
	}
	policyServer := NewPolicyServerFactory().WithName(string(name)).Build()

	policyServerValidator := policyServerValidator{logger: logr.Discard()}
	err := policyServerValidator.validate(t.Context(), policyServer)
	require.ErrorContains(t, err, "the PolicyServer name cannot be longer than 63 characters")
}

func TestPolicyServerValidateMinAvailableMaxUnavailable(t *testing.T) {
	policyServer := NewPolicyServerFactory().
		WithMinAvailable(ptr.To(intstr.FromInt(2))).
		WithMaxUnavailable(ptr.To(intstr.FromInt(2))).
		Build()

	policyServerValidator := policyServerValidator{logger: logr.Discard()}

	err := policyServerValidator.validate(t.Context(), policyServer)
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
				err := k8sClient.Create(t.Context(), test.secret)
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
			err := policyServerValidator.validate(t.Context(), policyServer)

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
			err := policyServerValidator.validate(t.Context(), policyServer)

			if test.error != "" {
				require.ErrorContains(t, err, test.error)
			}
		})
	}
}

func TestPolicyServerValidateSigstoreTrustConfig(t *testing.T) {
	tests := []struct {
		name      string
		configMap *corev1.ConfigMap
		error     string
	}{
		{
			name:      "missing ConfigMap",
			configMap: nil,
			error:     "cannot get spec.sigstoreTrustConfig ConfigMap",
		},
		{
			name: "ConfigMap missing required key",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sigstore-config",
					Namespace: "default",
				},
				Data: map[string]string{
					"wrong-key": fakeSigstoreTrustConfig,
				},
			},
			error: "does not contain required key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().Build()

			if test.configMap != nil {
				err := k8sClient.Create(t.Context(), test.configMap)
				require.NoError(t, err)
			}

			policyServer := NewPolicyServerFactory().
				WithSigstoreTrustConfigMap("sigstore-config").
				Build()

			policyServerValidator := policyServerValidator{
				deploymentsNamespace: "default",
				k8sClient:            k8sClient,
				logger:               logr.Discard(),
			}
			err := policyServerValidator.validate(t.Context(), policyServer)

			require.Error(t, err)
			require.ErrorContains(t, err, test.error)
		})
	}
}

func TestPolicyServerValidateNamespacedPoliciesCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
		valid        bool
		error        string
	}{
		{
			name:         "nil capabilities (not set)",
			capabilities: nil,
			valid:        true,
		},
		{
			name:         "empty capabilities",
			capabilities: []string{},
			valid:        true,
		},
		{
			name:         "wildcard all",
			capabilities: []string{"*"},
			valid:        true,
		},
		{
			name:         "category wildcard",
			capabilities: []string{"oci/*"},
			valid:        true,
		},
		{
			name:         "versioned category wildcard",
			capabilities: []string{"oci/v1/*"},
			valid:        true,
		},
		{
			name:         "specific capability",
			capabilities: []string{"oci/v1/verify"},
			valid:        true,
		},
		{
			name:         "multiple valid capabilities",
			capabilities: []string{"oci/*", "net/v1/dns_lookup_host", "crypto/v1/is_certificate_trusted"},
			valid:        true,
		},
		{
			name:         "all known categories",
			capabilities: []string{"oci/*", "kubernetes/*", "net/*", "crypto/*"},
			valid:        true,
		},
		{
			name:         "empty string",
			capabilities: []string{""},
			valid:        false,
			error:        "capability must not be empty",
		},
		{
			name:         "invalid category",
			capabilities: []string{"unknown/v1/foo"},
			valid:        false,
			error:        "unknown segment",
		},
		{
			name:         "invalid wildcard at category level",
			capabilities: []string{"oci*"},
			valid:        false,
			error:        "wildcard \"*\" is only allowed as the last path segment",
		},
		{
			name:         "invalid wildcard in middle",
			capabilities: []string{"oci/*/verify"},
			valid:        false,
			error:        "wildcard \"*\" is only allowed as the last path segment",
		},
		{
			name:         "invalid partial wildcard",
			capabilities: []string{"oci/v1/oci_*"},
			valid:        false,
			error:        "wildcard \"*\" is only allowed as the last path segment",
		},
		{
			name:         "unknown version segment",
			capabilities: []string{"oci/v3/verify"},
			valid:        false,
			error:        "unknown segment \"v3\"",
		},
		{
			name:         "unknown operation",
			capabilities: []string{"oci/v1/unknown_op"},
			valid:        false,
			error:        "unknown segment \"unknown_op\"",
		},
		{
			name:         "incomplete path without wildcard",
			capabilities: []string{"oci/v1"},
			valid:        false,
			error:        "not a complete capability path",
		},
		{
			name:         "kubernetes with spurious version segment",
			capabilities: []string{"kubernetes/v1/can_i"},
			valid:        false,
			error:        "unknown segment \"v1\"",
		},
		{
			name:         "valid kubernetes operation",
			capabilities: []string{"kubernetes/can_i"},
			valid:        true,
		},
		{
			name:         "valid kubernetes operation",
			capabilities: []string{"kubernetes/can_i/have_dessert"},
			valid:        false,
			error:        "is a complete capability path and cannot have further segments",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyServer := NewPolicyServerFactory().
				WithNamespacedPoliciesCapabilities(test.capabilities).
				Build()

			policyServerValidator := policyServerValidator{logger: logr.Discard()}
			err := policyServerValidator.validate(t.Context(), policyServer)

			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorContains(t, err, test.error)
			}
		})
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name        string
		webhookPort *int32
		readiness   *int32
		metrics     *int32
		errContains string
	}{
		{
			name:        "all defaults, no conflict",
			errContains: "",
		},
		{
			name:        "webhookPort equals readinessProbePort",
			webhookPort: ptr.To[int32](8081),
			readiness:   ptr.To[int32](8081),
			errContains: "readinessProbePort must differ from webhookPort",
		},
		{
			name:        "webhookPort and readinessProbePort distinct custom values",
			webhookPort: ptr.To[int32](9443),
			readiness:   ptr.To[int32](9081),
			errContains: "",
		},
		{
			// metricsPort is a Service-layer-only setting and cannot conflict
			// with pod-side ports (webhookPort, readinessProbePort).
			name:        "metricsPort equal to webhookPort is allowed",
			webhookPort: ptr.To[int32](8080),
			metrics:     ptr.To[int32](8080),
			errContains: "",
		},
		{
			// metricsPort is a Service-layer-only setting and cannot conflict
			// with pod-side ports (webhookPort, readinessProbePort).
			name:        "metricsPort equal to readinessProbePort is allowed",
			readiness:   ptr.To[int32](9000),
			metrics:     ptr.To[int32](9000),
			errContains: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().Build()
			builder := NewPolicyServerFactory()
			if test.webhookPort != nil {
				builder = builder.WithWebhookPort(*test.webhookPort)
			}
			if test.readiness != nil {
				builder = builder.WithReadinessProbePort(*test.readiness)
			}
			if test.metrics != nil {
				builder = builder.WithMetricsPort(*test.metrics)
			}
			policyServer := builder.Build()

			validator := policyServerValidator{
				deploymentsNamespace: "default",
				k8sClient:            k8sClient,
				logger:               logr.Discard(),
			}
			err := validator.validate(t.Context(), policyServer)

			if test.errContains != "" {
				require.ErrorContains(t, err, test.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
