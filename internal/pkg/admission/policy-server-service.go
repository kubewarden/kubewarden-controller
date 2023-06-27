package admission

import (
	"context"
	"fmt"
	"os"
	"strconv"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

var (
	// This is the port where the Policy Server service will be exposing metrics. Can be overridden
	// by an environment variable KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT
	metricsPort = constants.PolicyServerMetricsPort
)

func init() {
	envMetricsPort := os.Getenv(constants.PolicyServerMetricsPortEnvVar)
	if envMetricsPort != "" {
		var err error
		metricsPortInt32, err := strconv.ParseInt(envMetricsPort, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "port %s provided in %s envvar cannot be parsed as integer: %v. Aborting.\n", envMetricsPort, constants.PolicyServerMetricsPortEnvVar, err)
			os.Exit(1)
		}
		metricsPort = int(metricsPortInt32)
	}
}

func (r *Reconciler) reconcilePolicyServerService(ctx context.Context, policyServer *policiesv1.PolicyServer) error {
	service := r.service(policyServer)
	err := r.Client.Create(ctx, service)

	if err != nil && apierrors.IsAlreadyExists(err) {
		err = r.Client.Update(ctx, service)
	}
	if err == nil {
		return nil
	}
	return fmt.Errorf("cannot reconcile policy-server service: %w", err)
}

func (r *Reconciler) service(policyServer *policiesv1.PolicyServer) *corev1.Service {
	svc := corev1.Service{
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
					Name:       "policy-server",
					Port:       constants.PolicyServerPort,
					TargetPort: intstr.FromInt(constants.PolicyServerPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				constants.AppLabelKey: policyServer.AppLabel(),
			},
		},
	}
	if r.MetricsEnabled {
		svc.Spec.Ports = append(
			svc.Spec.Ports,
			corev1.ServicePort{
				Name:     "metrics",
				Port:     int32(metricsPort),
				Protocol: corev1.ProtocolTCP,
			},
		)
	}
	return &svc
}
