package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list;watch;create;update;patch

func (r *Reconciler) reconcileMutatingWebhookConfiguration(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
	policyServerName string) error {
	webhook := r.mutatingWebhookConfiguration(clusterAdmissionPolicy, admissionSecret, policyServerName)
	err := r.Client.Create(ctx, webhook)
	if err == nil {
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		return r.updateMutatingWebhook(ctx, clusterAdmissionPolicy, webhook)
	}
	return fmt.Errorf("cannot reconcile mutating webhook: %w", err)
}

func (r *Reconciler) updateMutatingWebhook(ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	newWebhook *admissionregistrationv1.MutatingWebhookConfiguration) error {

	var originalWebhook admissionregistrationv1.MutatingWebhookConfiguration

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
			return fmt.Errorf("cannot patch mutating webhook: %w", err)
		}
	}

	return nil
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
