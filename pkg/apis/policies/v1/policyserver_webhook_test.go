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
	"errors"
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
				"cpu":    resource.MustParse("1Gi"),
				"memory": resource.MustParse("1Gi"),
			},
		},
	}

	policyServer.Default()

	assert.Contains(t, policyServer.Finalizers, constants.KubewardenFinalizer)
	assert.Equal(t, corev1.ResourceList{
		"cpu":    resource.MustParse("1Gi"),
		"memory": resource.MustParse("1Gi"),
	}, policyServer.Spec.Requests)
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
		Name        string
		Limits      corev1.ResourceList
		Requests    corev1.ResourceList
		ExpectedErr error
	}{
		{
			Name:        "valid",
			Limits:      corev1.ResourceList{"cpu": resource.MustParse("1Gi")},
			Requests:    corev1.ResourceList{"cpu": resource.MustParse("500Mi")},
			ExpectedErr: nil,
		},
		{
			Name:        "negative limit",
			Limits:      corev1.ResourceList{"cpu": resource.MustParse("-1Gi")},
			Requests:    corev1.ResourceList{"cpu": resource.MustParse("500Mi")},
			ExpectedErr: errors.New("cpu limit must be greater than or equal to 0"),
		},
		{
			Name:        "negative request",
			Limits:      corev1.ResourceList{"cpu": resource.MustParse("1Gi")},
			Requests:    corev1.ResourceList{"cpu": resource.MustParse("-500Mi")},
			ExpectedErr: errors.New("cpu request must be greater than or equal to 0"),
		},
		{
			Name:        "request greater than limit",
			Limits:      corev1.ResourceList{"cpu": resource.MustParse("1Gi")},
			Requests:    corev1.ResourceList{"cpu": resource.MustParse("2Gi")},
			ExpectedErr: errors.New("request must be less than or equal to cpu limit"),
		},
	}

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			policyServer := &PolicyServer{
				Spec: PolicyServerSpec{
					Limits:   test.Limits,
					Requests: test.Requests,
				},
			}
			policyServerValidator := policyServerValidator{
				k8sClient:            nil,
				deploymentsNamespace: "default",
			}
			err := policyServerValidator.validate(context.Background(), policyServer)
			assert.Equal(t, err, test.ExpectedErr)
		})
	}
}
