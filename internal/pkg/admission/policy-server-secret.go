package admission

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileSecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}

	return fmt.Errorf("error reconciling policy-server Secret: %w", err)
}

type generateCAFunc = func() ([]byte, *admissionregistration.KeyPair, error)
type pemEncodeCertificateFunc = func(certificate []byte) ([]byte, error)

func (r *Reconciler) fetchOrInitializePolicyServerCARootSecret(ctx context.Context, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.PolicyServerCARootSecretName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		return r.buildPolicyServerCARootSecret(generateCA, pemEncodeCertificate)
	}
	policyServerSecret.ResourceVersion = ""
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize Policy Server secret: %w", err)
	}

	return &policyServerSecret, nil
}

func (r *Reconciler) buildPolicyServerCARootSecret(generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
	ca, caPrivateKey, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}
	caPEMEncoded, err := pemEncodeCertificate(ca)
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}
	secretContents := map[string]string{
		constants.PolicyServerCARootPemName:            string(caPEMEncoded),
		constants.PolicyServerCARootPrivateKeyCertName: caPrivateKey.PrivateKey,
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: r.DeploymentsNamespace,
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}
