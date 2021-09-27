package admission

import (
	"context"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"path/filepath"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;create;update;patch

func (r *Reconciler) reconcileValidatingWebhookConfiguration(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
	policyServerName string) error {
	webhook := r.validatingWebhookConfiguration(clusterAdmissionPolicy, admissionSecret, policyServerName)
	err := r.Client.Create(ctx, webhook)
	if err == nil {
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		return r.updateValidatingWebhook(ctx, clusterAdmissionPolicy, webhook)
	}
	return fmt.Errorf("cannot reconcile validating webhook: %w", err)
}

func (r *Reconciler) updateValidatingWebhook(ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	newWebhook *admissionregistrationv1.ValidatingWebhookConfiguration) error {
	var originalWebhook admissionregistrationv1.ValidatingWebhookConfiguration

	err := r.Client.Get(ctx, client.ObjectKey{
		Name: clusterAdmissionPolicy.Name,
	}, &originalWebhook)
	if err != nil && apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve mutating webhook: %w", err)
	}

	if !reflect.DeepEqual(originalWebhook.Webhooks, newWebhook.Webhooks) {
		patch := originalWebhook.DeepCopy()
		patch.Webhooks = newWebhook.Webhooks
		err = r.Client.Patch(ctx, patch, client.MergeFrom(&originalWebhook))
		if err != nil {
			return fmt.Errorf("cannot patch validating webhook: %w", err)
		}
	}

	return nil
}

func (r *Reconciler) validatingWebhookConfiguration(
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
	policyServerName string) *admissionregistrationv1.ValidatingWebhookConfiguration {
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
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
			Labels: map[string]string{
				"kubewarden": "true",
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: fmt.Sprintf("%s.kubewarden.admission", clusterAdmissionPolicy.Name),
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.PolicyServerCARootPemName],
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
