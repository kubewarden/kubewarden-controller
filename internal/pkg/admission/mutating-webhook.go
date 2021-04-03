package admission

import (
	"context"
	"fmt"
	"path/filepath"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubewardenv1alpha1 "github.com/kubewarden/kubewarden-controller/api/v1alpha1"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileMutatingWebhookRegistration(
	ctx context.Context,
	clusterAdmissionPolicy *kubewardenv1alpha1.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret) error {
	err := r.Client.Create(ctx, r.mutatingWebhookRegistration(clusterAdmissionPolicy, admissionSecret))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("cannot reconcile mutating webhook: %w", err)
}

func (r *Reconciler) mutatingWebhookRegistration(
	clusterAdmissionPolicy *kubewardenv1alpha1.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
) *admissionregistrationv1.MutatingWebhookConfiguration {
	admissionPath := filepath.Join("/validate", clusterAdmissionPolicy.Name)
	admissionPort := int32(constants.PolicyServerPort)

	service := admissionregistrationv1.ServiceReference{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerServiceName,
		Path:      &admissionPath,
		Port:      &admissionPort,
	}
	operationTypes := r.operationTypes(clusterAdmissionPolicy)

	var failurePolicy admissionregistrationv1.FailurePolicyType
	switch clusterAdmissionPolicy.Spec.FailurePolicy {
	case string(admissionregistrationv1.Fail):
		failurePolicy = admissionregistrationv1.Fail
	case string(admissionregistrationv1.Ignore):
		failurePolicy = admissionregistrationv1.Ignore
	default:
		r.Log.Info("admissionRegistration",
			"unknown failurePolicy", clusterAdmissionPolicy.Spec.FailurePolicy,
			"forcing mode", admissionregistrationv1.Fail,
		)
		failurePolicy = admissionregistrationv1.Fail
	}

	sideEffects := admissionregistrationv1.SideEffectClassNone
	apiGroups := clusterAdmissionPolicy.Spec.APIGroups
	if len(apiGroups) == 0 {
		apiGroups = []string{"*"}
	}
	apiVersions := clusterAdmissionPolicy.Spec.APIVersions
	if len(apiVersions) == 0 {
		apiVersions = []string{"*"}
	}
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
			Labels: map[string]string{
				"kubewarden": "true",
			},
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: fmt.Sprintf("%s.kubewarden.admission", clusterAdmissionPolicy.Name),
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.PolicyServerCASecretKeyName],
				},
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: operationTypes,
						Rule: admissionregistrationv1.Rule{
							APIGroups:   apiGroups,
							APIVersions: apiVersions,
							Resources:   clusterAdmissionPolicy.Spec.Resources,
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}
}
