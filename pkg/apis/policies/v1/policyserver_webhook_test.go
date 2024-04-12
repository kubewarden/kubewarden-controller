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

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestDefault(t *testing.T) {
	policyServer := &PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-server",
		},
		Spec: PolicyServerSpec{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("1Gi"),
			},
		},
	}

	policyServer.Default()

	assert.Contains(t, policyServer.Finalizers, constants.KubewardenFinalizer)
}

func TestValidatePolicyServerName(t *testing.T) {
	name := make([]byte, 64)
	for i := range name {
		name[i] = 'a'
	}
	policyServer := &PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(name),
			Namespace: "default",
		},
		Spec: PolicyServerSpec{
			Image:    "image",
			Replicas: 1,
		},
	}
	policyServerValidator := policyServerValidator{
		k8sClient:            nil,
		deploymentsNamespace: "default",
	}
	err := policyServerValidator.validate(context.Background(), policyServer)
	require.ErrorContains(t, err, "the PolicyServer name cannot be longer than 63 characters")
}

func TestValidateMinAvailable(t *testing.T) {
	intStrValue := intstr.FromInt(2)
	policyServer := &PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-server",
			Namespace: "default",
		},
		Spec: PolicyServerSpec{
			Image:          "image",
			Replicas:       1,
			MinAvailable:   &intStrValue,
			MaxUnavailable: &intStrValue,
		},
	}
	policyServerValidator := policyServerValidator{
		k8sClient:            nil,
		deploymentsNamespace: "default",
	}
	err := policyServerValidator.validate(context.Background(), policyServer)
	require.ErrorContains(t, err, "minAvailable and maxUnavailable cannot be both set")
}

func TestValidateLimitsAndRequests(t *testing.T) {
	testCases := []struct {
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

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			policyServer := &PolicyServer{
				Spec: PolicyServerSpec{
					Limits:   test.limits,
					Requests: test.requests,
				},
			}
			policyServerValidator := policyServerValidator{
				k8sClient:            nil,
				deploymentsNamespace: "default",
			}
			err := policyServerValidator.validate(context.Background(), policyServer)

			if test.error != "" {
				require.ErrorContains(t, err, test.error)
			}
		})
	}
}
