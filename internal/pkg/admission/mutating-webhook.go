package admission

import (
	"context"
	"fmt"
	"path/filepath"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	chimerav1alpha1 "github.com/chimera-kube/chimera-controller/api/v1alpha1"
	"github.com/chimera-kube/chimera-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileMutatingWebhookRegistration(
	ctx context.Context,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
	admissionSecret *corev1.Secret) error {
	err := r.Client.Create(ctx, r.mutatingWebhookRegistration(admissionPolicy, admissionSecret))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("cannot reconcile mutating webhook: %w", err)
}

func (r *Reconciler) mutatingWebhookRegistration(
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
	admissionSecret *corev1.Secret,
) *admissionregistrationv1.MutatingWebhookConfiguration {
	admissionPath := filepath.Join("/validate", admissionPolicy.Name)
	admissionPort := int32(constants.PolicyServerPort)

	service := admissionregistrationv1.ServiceReference{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerServiceName,
		Path:      &admissionPath,
		Port:      &admissionPort,
	}
	operationTypes := r.operationTypes(admissionPolicy)

	var failurePolicy admissionregistrationv1.FailurePolicyType
	switch admissionPolicy.Spec.FailurePolicy {
	case string(admissionregistrationv1.Fail):
		failurePolicy = admissionregistrationv1.Fail
	case string(admissionregistrationv1.Ignore):
		failurePolicy = admissionregistrationv1.Ignore
	default:
		r.Log.Info("admissionRegistration",
			"unknown failurePolicy", admissionPolicy.Spec.FailurePolicy,
			"forcing mode", admissionregistrationv1.Fail,
		)
		failurePolicy = admissionregistrationv1.Fail
	}

	sideEffects := admissionregistrationv1.SideEffectClassNone
	apiGroups := admissionPolicy.Spec.APIGroups
	if len(apiGroups) == 0 {
		apiGroups = []string{"*"}
	}
	apiVersions := admissionPolicy.Spec.APIVersions
	if len(apiVersions) == 0 {
		apiVersions = []string{"*"}
	}
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: admissionPolicy.Name,
			Labels: map[string]string{
				"chimera": "true",
			},
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: fmt.Sprintf("%s.chimera.admission", admissionPolicy.Name),
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
							Resources:   admissionPolicy.Spec.Resources,
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
