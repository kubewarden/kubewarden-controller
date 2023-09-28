package admission

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/certificates"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileCASecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}

	return fmt.Errorf("error reconciling policy-server CA Secret: %w", err)
}

func (r *Reconciler) fetchOrInitializePolicyServerCASecret(ctx context.Context, policyServerName string, caSecret *corev1.Secret) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      policyServerName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		secret, err := r.buildPolicyServerCASecret(policyServerName, caSecret)
		if err != nil {
			return secret, fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
		}
		return secret, nil
	}
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}

	policyServerSecret.ResourceVersion = ""

	return &policyServerSecret, nil
}

func (r *Reconciler) buildPolicyServerCASecret(policyServerName string, caSecret *corev1.Secret) (*corev1.Secret, error) {
	admissionregCA, err := extractCaFromSecret(caSecret)
	if err != nil {
		return nil, err
	}
	servingCert, servingKey, err := certificates.GenerateCert(
		admissionregCA.CaCertBytes,
		[]string{fmt.Sprintf("%s.%s.svc", policyServerName, r.DeploymentsNamespace)},
		admissionregCA.CaPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServerName, err)
	}
	secretContents := map[string]string{
		constants.PolicyServerTLSCert: servingCert.String(),
		constants.PolicyServerTLSKey:  servingKey.String(),
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServerName,
			Namespace: r.DeploymentsNamespace,
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}

func extractCaFromSecret(caSecret *corev1.Secret) (*certificates.CA, error) {
	caCertBytes, hasCARootCert := caSecret.Data[constants.PolicyServerCARootCACert]
	if !hasCARootCert {
		return nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("CA certificate could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKeyBytes, hasCARootCertKey := caSecret.Data[constants.PolicyServerCARootPrivateKeyCertName]
	if !hasCARootCertKey {
		return nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}
	return &certificates.CA{CaCert: *caCert, CaCertBytes: caCertBytes, CaPrivateKey: caPrivateKey}, nil
}

func (r *Reconciler) fetchOrInitializePolicyServerCARootSecret(ctx context.Context) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.PolicyServerCARootSecretName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		return r.buildPolicyServerCARootSecret()
	}
	policyServerSecret.ResourceVersion = ""
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}

	return &policyServerSecret, nil
}

func (r *Reconciler) buildPolicyServerCARootSecret() (*corev1.Secret, error) {
	rootCA, err := certificates.GenerateCA()
	if err != nil {
		return nil, errors.Join(errors.New("unable to create root ca"), err)
	}

	caPEMEncoded, err := rootCA.PEMEncodeCertificate()
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}

	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(rootCA.CaPrivateKey)
	secretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             rootCA.CaCertBytes,
		constants.PolicyServerCARootPemName:            caPEMEncoded.Bytes(),
		constants.PolicyServerCARootPrivateKeyCertName: caPrivateKeyBytes,
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: r.DeploymentsNamespace,
		},
		Data: secretContents,
		Type: corev1.SecretTypeOpaque,
	}, nil
}
