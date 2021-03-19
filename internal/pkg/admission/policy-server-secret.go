package admission

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chimera-kube/chimera-controller/internal/pkg/admissionregistration"
	"github.com/chimera-kube/chimera-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileSecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}

	return fmt.Errorf("error reconciling policy-server Secret: %w", err)
}

func (r *Reconciler) fetchOrInitializePolicyServerSecret(ctx context.Context) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.PolicyServerSecretName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		return r.buildPolicyServerSecret()
	}
	policyServerSecret.ResourceVersion = ""
	return &policyServerSecret,
		fmt.Errorf("cannot fetch or initialize Policy Server secret: %w", err)
}

func (r *Reconciler) buildPolicyServerSecret() (*corev1.Secret, error) {
	ca, caPrivateKey, err := admissionregistration.GenerateCA()
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}
	caPEMEncoded, err := admissionregistration.PemEncodeCertificate(ca)
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}
	servingCert, servingKey, err := admissionregistration.GenerateCert(
		ca,
		fmt.Sprintf("%s.%s.svc", constants.PolicyServerServiceName, r.DeploymentsNamespace),
		[]string{fmt.Sprintf("%s.%s.svc", constants.PolicyServerServiceName, r.DeploymentsNamespace)},
		caPrivateKey.Key())
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server certificate: %w", err)
	}
	secretContents := map[string]string{
		constants.PolicyServerTLSCert:         string(servingCert),
		constants.PolicyServerTLSKey:          string(servingKey),
		constants.PolicyServerCASecretKeyName: string(caPEMEncoded),
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerSecretName,
			Namespace: r.DeploymentsNamespace,
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}
