package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chimerav1alpha1 "github.com/chimera-kube/chimera-controller/api/v1alpha1"
	"github.com/chimera-kube/chimera-controller/internal/pkg/admissionregistration"
	"github.com/chimera-kube/chimera-controller/internal/pkg/constants"
	"github.com/chimera-kube/chimera-controller/internal/pkg/utils"
)

const (
	secretsContainerPath = "/pki"
)

type AdmissionReconciler struct {
	Client               client.Client
	DeploymentsNamespace string
}

type errorList []error

func (errorList errorList) Error() string {
	errors := []string{}
	for _, error := range errorList {
		errors = append(errors, error.Error())
	}
	return strings.Join(errors, ", ")
}

func (r *AdmissionReconciler) ReconcileDeletion(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	errors := errorList{}
	if err := r.Client.Delete(ctx, r.deployment(admissionPolicy)); err != nil && !apierrors.IsNotFound(err) {
		errors = append(errors, err)
	}
	admissionSecret, err := r.admissionSecret(admissionPolicy)
	if err == nil {
		if err := r.Client.Delete(ctx, admissionSecret); err != nil && !apierrors.IsNotFound(err) {
			errors = append(errors, err)
		}
	}
	if err := r.Client.Delete(ctx, r.admissionRegistration(admissionPolicy, admissionSecret)); err != nil && !apierrors.IsNotFound(err) {
		errors = append(errors, err)
	}
	if err := r.reconcileDeletionFinalizer(ctx, admissionPolicy); err != nil && !apierrors.IsNotFound(err) {
		errors = append(errors, err)
	}
	if len(errors) == 0 {
		return nil
	}
	return errors
}

func (r *AdmissionReconciler) Reconcile(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	admissionSecret, err := r.fetchOrInitializeSecret(ctx, admissionPolicy)
	if err != nil {
		return err
	}
	if err := r.reconcileSecret(ctx, admissionSecret); err != nil {
		return err
	}
	if err := r.reconcileDeployment(ctx, admissionPolicy); err != nil {
		return err
	}
	if err := r.reconcileService(ctx, admissionPolicy); err != nil {
		return err
	}
	return r.reconcileAdmissionRegistration(ctx, admissionPolicy, admissionSecret)
}

func (r *AdmissionReconciler) reconcileSecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (r *AdmissionReconciler) reconcileDeployment(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	err := r.Client.Create(ctx, r.deployment(admissionPolicy))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (r *AdmissionReconciler) reconcileService(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	err := r.Client.Create(ctx, r.service(admissionPolicy))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (r *AdmissionReconciler) reconcileAdmissionRegistration(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy, admissionSecret *corev1.Secret) error {
	err := r.Client.Create(ctx, r.admissionRegistration(admissionPolicy, admissionSecret))
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (r *AdmissionReconciler) reconcileDeletionFinalizer(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	admissionPolicy.Finalizers = utils.RemoveStringFromSlice(
		constants.AdmissionFinalizer,
		admissionPolicy.Finalizers,
	)
	return r.Client.Update(ctx, admissionPolicy)
}

func (r *AdmissionReconciler) namespace() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.DeploymentsNamespace,
		},
	}
}

func (r *AdmissionReconciler) fetchOrInitializeSecret(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) (*corev1.Secret, error) {
	admissionSecret := corev1.Secret{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.DeploymentsNamespace, Name: admissionPolicy.Name}, &admissionSecret)
	if err != nil && apierrors.IsNotFound(err) {
		return r.admissionSecret(admissionPolicy)
	}
	admissionSecret.ResourceVersion = ""
	return &admissionSecret, err
}

func (r *AdmissionReconciler) admissionSecret(admissionPolicy *chimerav1alpha1.AdmissionPolicy) (*corev1.Secret, error) {
	ca, caPrivateKey, err := admissionregistration.GenerateCA()
	if err != nil {
		return nil, err
	}
	caPEMEncoded, err := admissionregistration.PemEncodeCertificate(ca)
	if err != nil {
		return nil, err
	}
	servingCert, servingKey, err := admissionregistration.GenerateCert(ca, fmt.Sprintf("%s.%s.svc", admissionPolicy.Name, r.DeploymentsNamespace), []string{fmt.Sprintf("%s.%s.svc", admissionPolicy.Name, r.DeploymentsNamespace)}, caPrivateKey.Key())
	secretContents := map[string]string{
		constants.AdmissionCertSecretKeyName: string(servingCert),
		constants.AdmissionKeySecretKeyName:  string(servingKey),
		constants.AdmissionCASecretKeyName:   string(caPEMEncoded),
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      admissionPolicy.Name,
			Namespace: r.DeploymentsNamespace,
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}

func (r *AdmissionReconciler) deployment(admissionPolicy *chimerav1alpha1.AdmissionPolicy) *appsv1.Deployment {
	var webhookReplicas int32 = 1
	secretVolumeName := fmt.Sprintf("%s-secrets", admissionPolicy.Name)
	admissionContainer := corev1.Container{
		Name:  "chimera-admission",
		Image: constants.AdmissionImage,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      secretVolumeName,
				ReadOnly:  true,
				MountPath: secretsContainerPath,
			},
		},
		Env: []corev1.EnvVar{
			corev1.EnvVar{
				Name:  "CHIMERA_ADMISSION_NAME",
				Value: fmt.Sprintf("%s.admission.rule", admissionPolicy.Name),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_SKIP_ADMISSION_REGISTRATION",
				Value: "1",
			},
			corev1.EnvVar{
				Name:  "CHIMERA_CALLBACK_PORT",
				Value: fmt.Sprintf("%d", constants.AdmissionPort),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_VALIDATE_PATH",
				Value: constants.AdmissionPath,
			},
			corev1.EnvVar{
				Name:  "CHIMERA_CERT_FILE",
				Value: filepath.Join(secretsContainerPath, "admission-cert"),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_KEY_FILE",
				Value: filepath.Join(secretsContainerPath, "admission-key"),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_CA_BUNDLE",
				Value: filepath.Join(secretsContainerPath, "admission-ca"),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_API_GROUPS",
				Value: strings.Join(admissionPolicy.Spec.APIGroups, ","),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_API_VERSIONS",
				Value: strings.Join(admissionPolicy.Spec.APIVersions, ","),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_RESOURCES",
				Value: strings.Join(admissionPolicy.Spec.Resources, ","),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_OPERATIONS",
				Value: strings.Join(admissionPolicy.Spec.Operations, ","),
			},
			corev1.EnvVar{
				Name:  "CHIMERA_WASM_URI",
				Value: admissionPolicy.Spec.Module,
			},
		},
	}
	for envKey, envValue := range admissionPolicy.Spec.Env {
		admissionContainer.Env = append(
			admissionContainer.Env,
			corev1.EnvVar{
				Name:  fmt.Sprintf("CHIMERA_EXPORT_%s", envKey),
				Value: envValue,
			},
		)
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      admissionPolicy.Name,
			Namespace: r.DeploymentsNamespace,
			Labels:    constants.AdmissionLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &webhookReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: constants.AdmissionLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: constants.AdmissionLabels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{admissionContainer},
					Volumes: []corev1.Volume{
						{
							Name: secretVolumeName,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: admissionPolicy.Name,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *AdmissionReconciler) service(admissionPolicy *chimerav1alpha1.AdmissionPolicy) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      admissionPolicy.Name,
			Namespace: r.DeploymentsNamespace,
			Labels:    constants.AdmissionLabels,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:     constants.AdmissionPort,
					Protocol: corev1.ProtocolTCP,
				},
			},
			Selector: constants.AdmissionLabels,
		},
	}
}

func (r *AdmissionReconciler) operationTypes(admissionPolicy *chimerav1alpha1.AdmissionPolicy) []admissionregistrationv1.OperationType {
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

func (r *AdmissionReconciler) admissionRegistration(admissionPolicy *chimerav1alpha1.AdmissionPolicy, admissionSecret *corev1.Secret) *admissionregistrationv1.ValidatingWebhookConfiguration {
	admissionPort, admissionPath := constants.AdmissionPort, constants.AdmissionPath
	service := admissionregistrationv1.ServiceReference{
		Namespace: r.DeploymentsNamespace,
		Name:      admissionPolicy.Name,
		Path:      &admissionPath,
		Port:      &admissionPort,
	}
	operationTypes := r.operationTypes(admissionPolicy)
	failurePolicy := admissionregistrationv1.Fail
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
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: fmt.Sprintf("%s.chimera.admission", admissionPolicy.Name),
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.AdmissionCASecretKeyName],
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
