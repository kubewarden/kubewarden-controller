package admission

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type generateCAFunc = func() (*admissionregistration.CA, error)
type pemEncodeCertificateFunc = func(certificate []byte) ([]byte, error)
type generateCertFunc = func(ca []byte, commonName string, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error)

func (r *Reconciler) reconcileCASecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}

	return fmt.Errorf("error reconciling policy-server CA Secret: %w", err)
}

func (r *Reconciler) fetchOrInitializePolicyServerCASecret(ctx context.Context, policyServerName string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      policyServerName},
		&policyServerSecret)
	if err != nil && apierrors.IsNotFound(err) {
		secret, err := r.buildPolicyServerCASecret(policyServerName, caSecret, generateCert)
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

func (r *Reconciler) buildPolicyServerCASecret(policyServerName string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	admissionregCA, err := extractCaFromSecret(caSecret)
	if err != nil {
		return nil, err
	}
	servingCert, servingKey, err := generateCert(
		admissionregCA.CaCert,
		fmt.Sprintf("%s.%s.svc", policyServerName, r.DeploymentsNamespace),
		[]string{fmt.Sprintf("%s.%s.svc", policyServerName, r.DeploymentsNamespace)},
		admissionregCA.CaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServerName, err)
	}
	secretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
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

func extractCaFromSecret(caSecret *corev1.Secret) (*admissionregistration.CA, error) {
	caCert, ok := caSecret.Data[constants.PolicyServerCARootCACert]
	if !ok {
		return nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}
	caPrivateKeyBytes, ok := caSecret.Data[constants.PolicyServerCARootPrivateKeyCertName]
	if !ok {
		return nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}
	return &admissionregistration.CA{CaCert: caCert, CaPrivateKey: caPrivateKey}, nil
}

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
			fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}

	return &policyServerSecret, nil
}

func (r *Reconciler) buildPolicyServerCARootSecret(generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
	caRoot, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}
	caPEMEncoded, err := pemEncodeCertificate(caRoot.CaCert)
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}
	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(caRoot.CaPrivateKey)
	secretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             caRoot.CaCert,
		constants.PolicyServerCARootPemName:            caPEMEncoded,
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
