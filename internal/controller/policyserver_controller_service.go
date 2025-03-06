package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// This is the port where the Policy Server service will be exposing metrics. Can be overridden
// by an environment variable KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT.
func getMetricsPort() int32 {
	metricsPort := int32(constants.PolicyServerMetricsPort)
	envMetricsPort := os.Getenv(constants.PolicyServerMetricsPortEnvVar)
	if envMetricsPort != "" {
		var err error
		metricsPortInt32, err := strconv.ParseInt(envMetricsPort, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "port %s provided in %s envvar cannot be parsed as integer: %v. Aborting.\n", envMetricsPort, constants.PolicyServerMetricsPortEnvVar, err)
			os.Exit(1)
		}
		metricsPort = int32(metricsPortInt32)
	}
	return metricsPort
}

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
				TargetPort: intstr.FromInt(constants.PolicyServerPort),
				Protocol:   corev1.ProtocolTCP,
			},
			// Keep adding the old port to avoid breaking a cluster
			// during the upgrade to Kubewarden 1.23.0
			// TODO: remove this port with a future release
			{
				Name:       "policy-server-legacy",
				Port:       constants.PolicyServerPort,
				TargetPort: intstr.FromInt(constants.PolicyServerPort),
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
				Name:     "metrics",
				Port:     getMetricsPort(),
				Protocol: corev1.ProtocolTCP,
			},
		)
	}

	if err := controllerutil.SetOwnerReference(policyServer, svc, r.Client.Scheme()); err != nil {
		return errors.Join(errors.New("failed to set policy server service owner reference"), err)
	}

	return nil
}
