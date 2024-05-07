package admission

import (
	"context"
	"fmt"
	"path/filepath"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=create;delete;list;patch;watch

func (r *Reconciler) ReconcileValidatingWebhookConfiguration(
	ctx context.Context,
	policy policiesv1.Policy,
	admissionSecret *corev1.Secret,
	policyServerNameWithPrefix string,
) error {
	webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.GetUniqueName(),
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, webhook, func() error {
		admissionPath := filepath.Join("/validate", policy.GetUniqueName())
		admissionPort := int32(constants.PolicyServerPort)

		service := admissionregistrationv1.ServiceReference{
			Namespace: r.DeploymentsNamespace,
			Name:      policyServerNameWithPrefix,
			Path:      &admissionPath,
			Port:      &admissionPort,
		}

		sideEffects := policy.GetSideEffects()
		if sideEffects == nil {
			noneSideEffects := admissionregistrationv1.SideEffectClassNone
			sideEffects = &noneSideEffects
		}

		policyScope := "namespace"
		if policy.GetNamespace() == "" {
			policyScope = "cluster"
		}
		webhook.Name = policy.GetUniqueName()
		webhook.Labels = map[string]string{
			"kubewarden": "true",
			constants.WebhookConfigurationPolicyScopeLabelKey: policyScope,
		}
		webhook.Annotations = map[string]string{
			constants.WebhookConfigurationPolicyNameAnnotationKey:      policy.GetName(),
			constants.WebhookConfigurationPolicyNamespaceAnnotationKey: policy.GetNamespace(),
		}
		webhook.Webhooks = []admissionregistrationv1.ValidatingWebhook{
			{
				Name: fmt.Sprintf("%s.kubewarden.admission", policy.GetUniqueName()),
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.PolicyServerCARootPemName],
				},
				Rules:                   policy.GetRules(),
				FailurePolicy:           policy.GetFailurePolicy(),
				MatchPolicy:             policy.GetMatchPolicy(),
				NamespaceSelector:       policy.GetUpdatedNamespaceSelector(r.DeploymentsNamespace),
				ObjectSelector:          policy.GetObjectSelector(),
				SideEffects:             sideEffects,
				TimeoutSeconds:          policy.GetTimeoutSeconds(),
				AdmissionReviewVersions: []string{"v1"},
			},
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot reconcile validating webhook: %w", err)
	}
	return nil
}
