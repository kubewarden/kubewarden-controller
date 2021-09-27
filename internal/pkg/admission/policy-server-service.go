package admission

import (
	"context"
	"fmt"
	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcilePolicyServerService(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) error {
	err := r.Client.Create(ctx, r.service(policyServer))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("cannot reconcile policy-server service: %w", err)
}

func (r *Reconciler) service(policyServer *policiesv1alpha2.PolicyServer) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
			Labels: map[string]string{
				constants.AppLabelKey: policyServer.AppLabel(),
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:     constants.PolicyServerPort,
					Protocol: corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				constants.AppLabelKey: policyServer.AppLabel(),
			},
		},
	}
}
