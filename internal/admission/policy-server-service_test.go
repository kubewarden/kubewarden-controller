package admission

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

func TestServiceOwnerReference(t *testing.T) {
	reconciler := newReconciler([]client.Object{}, false, false)
	policyServer := &policiesv1.PolicyServer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "policies.kubewarden.io/v1",
			Kind:       "PolicyServer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-server",
			UID:  "uid",
		},
	}
	service := &corev1.Service{}

	err := reconciler.updateService(service, policyServer)

	require.NoError(t, err)
	require.Equal(t, policyServer.GetName(), service.OwnerReferences[0].Name)
	require.Equal(t, policyServer.GetUID(), service.OwnerReferences[0].UID)
	require.Equal(t, policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String(), service.OwnerReferences[0].APIVersion)
	require.Equal(t, policyServer.GetObjectKind().GroupVersionKind().Kind, service.OwnerReferences[0].Kind)
}

func TestServiceConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		metricsEnabled bool
	}{
		{"with metrics enabled", true},
		{"with metrics disabled", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciler := newReconciler(nil, test.metricsEnabled, true)
			service := &corev1.Service{}
			policyServer := &policiesv1.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			}
			err := reconciler.updateService(service, policyServer)
			require.NoError(t, err)
			require.Equal(t, policyServer.AppLabel(), service.Labels[constants.AppLabelKey])
			require.Equal(t, policyServer.NameWithPrefix(), service.Name)
			require.Equal(t, reconciler.DeploymentsNamespace, service.Namespace)
			require.Contains(t, service.Spec.Ports, corev1.ServicePort{
				Name:       "policy-server",
				Port:       constants.PolicyServerPort,
				TargetPort: intstr.FromInt(constants.PolicyServerPort),
				Protocol:   corev1.ProtocolTCP,
			})
			require.Equal(t, map[string]string{
				constants.AppLabelKey: policyServer.AppLabel(),
			}, service.Spec.Selector)

			metricsPort := corev1.ServicePort{
				Name:     "metrics",
				Port:     int32(metricsPort),
				Protocol: corev1.ProtocolTCP,
			}
			if test.metricsEnabled {
				require.Contains(t, service.Spec.Ports, metricsPort)
			} else {
				require.NotContains(t, service.Spec.Ports, metricsPort)
			}
		})
	}
}
