package admission

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcilePolicyServerService(ctx context.Context, policyServerName string) error {
	err := r.Client.Create(ctx, r.service(policyServerName))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("cannot reconcile policy-server service: %w", err)
}

func (r *Reconciler) service(policyServerName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServerName,
			Namespace: r.DeploymentsNamespace,
			Labels:    constants.PolicyServerLabels,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:     constants.PolicyServerPort,
					Protocol: corev1.ProtocolTCP,
				},
			},
			Selector: constants.PolicyServerLabels,
		},
	}
}
