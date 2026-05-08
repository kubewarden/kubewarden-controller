package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

func (r *PolicyServerReconciler) reconcilePolicyServerService(ctx context.Context, policyServer *policiesv1.PolicyServer) error {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, &svc, func() error {
		return r.updateService(&svc, policyServer)
	})
	if err != nil {
		return fmt.Errorf("cannot reconcile policy-server service: %w", err)
	}
	return nil
}

func (r *PolicyServerReconciler) updateService(svc *corev1.Service, policyServer *policiesv1.PolicyServer) error {
	commonLabels := policyServer.CommonLabels()

	svc.Name = policyServer.NameWithPrefix()
	svc.Namespace = r.DeploymentsNamespace
	templateLabels := map[string]string{
		constants.PolicyServerLabelKey: policyServer.Name,
	}
	for key, value := range policyServer.CommonLabels() {
		templateLabels[key] = value
	}
	svc.Labels = templateLabels

	svc.Spec = corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:       "policy-server",
				Port:       constants.PolicyServerServicePort,
				TargetPort: intstr.FromInt32(policyServer.EffectiveWebhookPort()),
				Protocol:   corev1.ProtocolTCP,
			},
		},
		Selector: map[string]string{
			constants.InstanceLabelKey: commonLabels[constants.InstanceLabelKey],
			constants.PartOfLabelKey:   commonLabels[constants.PartOfLabelKey],
		},
	}
	if r.MetricsEnabled {
		svc.Spec.Ports = append(
			svc.Spec.Ports,
			corev1.ServicePort{
				Name: "metrics",
				// spec.metricsPort customizes the Service Port (the port Prometheus
				// scrapes externally). It does not affect the pod-side port.
				Port: policyServer.EffectiveMetricsPort(r.PolicyServerMetricsPort),
				// TargetPort is intentionally fixed at the controller-wide default and
				// does NOT follow spec.metricsPort. When the OpenTelemetry sidecar mode
				// is enabled, the injected sidecar (one per pod) always exports
				// Prometheus metrics on this fixed cluster-wide port. Routing traffic
				// to a different pod port would break sidecar-mode metrics scraping.
				TargetPort: intstr.FromInt32(r.PolicyServerMetricsPort),
				Protocol:   corev1.ProtocolTCP,
			},
		)
	}

	if err := controllerutil.SetOwnerReference(policyServer, svc, r.Client.Scheme()); err != nil {
		return errors.Join(errors.New("failed to set policy server service owner reference"), err)
	}

	return nil
}
