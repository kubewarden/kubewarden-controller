package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	chimerav1alpha1 "github.com/chimera-kube/chimera-controller/api/v1alpha1"
	"github.com/chimera-kube/chimera-controller/internal/pkg/constants"
)

func (r *AdmissionReconciler) reconcileAdmissionRegistration(
	ctx context.Context,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
	admissionSecret *corev1.Secret) error {
	err := r.Client.Create(ctx, r.admissionRegistration(admissionPolicy, admissionSecret))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return fmt.Errorf("cannot reconcile validating webhook: %w", err)
}

func (r *AdmissionReconciler) admissionRegistration(admissionPolicy *chimerav1alpha1.AdmissionPolicy, admissionSecret *corev1.Secret) *admissionregistrationv1.ValidatingWebhookConfiguration {
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
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: admissionPolicy.Name,
			Labels: map[string]string{
				"chimera": "true",
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
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

func (r *AdmissionReconciler) operationTypes(
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) []admissionregistrationv1.OperationType {
	operationTypes := []admissionregistrationv1.OperationType{}
	for _, operation := range admissionPolicy.Spec.Operations {
		switch strings.ToUpper(operation) {
		case "*":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.OperationAll,
			)
		case "CREATE":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Create,
			)
		case "UPDATE":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Update,
			)
		case "DELETE":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Delete,
			)
		case "CONNECT":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Connect,
			)
		default:
			continue
		}
	}
	return operationTypes
}
