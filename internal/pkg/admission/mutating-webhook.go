package admission

import (
	"context"
	"fmt"
	"path/filepath"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileMutatingWebhookConfiguration(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
	policyServerName string) error {
	err := r.Client.Create(ctx, r.mutatingWebhookConfiguration(clusterAdmissionPolicy, admissionSecret, policyServerName))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("cannot reconcile mutating webhook: %w", err)
}

func (r *Reconciler) mutatingWebhookConfiguration(
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
	policyServerName string) *admissionregistrationv1.MutatingWebhookConfiguration {
	admissionPath := filepath.Join("/validate", clusterAdmissionPolicy.Name)
	admissionPort := int32(constants.PolicyServerPort)

	service := admissionregistrationv1.ServiceReference{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServerName,
		Path:      &admissionPath,
		Port:      &admissionPort,
	}

	sideEffects := clusterAdmissionPolicy.Spec.SideEffects
	if sideEffects == nil {
		noneSideEffects := admissionregistrationv1.SideEffectClassNone
		sideEffects = &noneSideEffects
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
					CABundle: admissionSecret.Data[constants.PolicyServerCARootSecretName],
				},
				Rules:                   clusterAdmissionPolicy.Spec.Rules,
				FailurePolicy:           clusterAdmissionPolicy.Spec.FailurePolicy,
				MatchPolicy:             clusterAdmissionPolicy.Spec.MatchPolicy,
				NamespaceSelector:       clusterAdmissionPolicy.Spec.NamespaceSelector,
				ObjectSelector:          clusterAdmissionPolicy.Spec.ObjectSelector,
				SideEffects:             sideEffects,
				TimeoutSeconds:          clusterAdmissionPolicy.Spec.TimeoutSeconds,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}
}
