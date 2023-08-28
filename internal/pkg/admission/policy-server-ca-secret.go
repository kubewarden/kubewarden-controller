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
type generateCertFunc = func(ca []byte, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error)

func (r *Reconciler) reconcileCASecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	if err == nil || apierrors.IsAlreadyExists(err) {
		return nil
	}

	return fmt.Errorf("error reconciling policy-server CA Secret: %w", err)
}

func ReconcileSecret(ctx context.Context, clusterClient client.Client, secret *corev1.Secret) error {
	err := clusterClient.Create(ctx, secret)
	if err != nil && apierrors.IsAlreadyExists(err) {
		if err := clusterClient.Update(ctx, secret); err != nil {
			return fmt.Errorf("failed to update secret \"%s\": %s", secret.Name, err.Error())
		}
		return nil
	}
	if err == nil {
		return nil
	}
	return fmt.Errorf("error reconciling policy-server CA Secret: %w", err)
}

func (r *Reconciler) fetchOrInitializePolicyServerCASecret(ctx context.Context, policyServerName string, policyServerServiceName string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	secret, initialized, err := FetchOrInitializeCertificate(ctx, r.Client, policyServerServiceName, r.DeploymentsNamespace, policyServerServiceName, caSecret, generateCert)
	if initialized {
		// label used to detect when the policy server certificate
		// change and triggering the webhook's caBundle updates
		secret.Labels[constants.PolicyServerLabelKey] = policyServerName
	}
	return secret, err
}

func ExtractCertificateData(secret *corev1.Secret) ([]byte, []byte, error) {
	certificate, ok := secret.Data[constants.CARootCACertPem]
	if !ok {
		return []byte{}, []byte{}, fmt.Errorf("failed to initialize root CA certificate")
	}
	privateKey, ok := secret.Data[constants.CARootPrivateKeyCertName]
	if !ok {
		return []byte{}, []byte{}, fmt.Errorf("failed to initialize root CA private key")
	}
	return certificate, privateKey, nil
}

func extractCaFromSecret(caSecret *corev1.Secret) (*admissionregistration.CA, error) {
	caCert, ok := caSecret.Data[constants.CARootCACert]
	if !ok {
		return nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}
	caPrivateKeyBytes, ok := caSecret.Data[constants.CARootPrivateKeyCertName]
	if !ok {
		return nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}
	return &admissionregistration.CA{CaCert: caCert, CaPrivateKey: caPrivateKey}, nil
}

func buildCARootSecret(namespace string, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
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
		constants.CARootCACert:             caRoot.CaCert,
		constants.CARootCACertPem:          caPEMEncoded,
		constants.CARootPrivateKeyCertName: caPrivateKeyBytes,
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.KubewardenCARootSecretName,
			Namespace: namespace,
		},
		Data: secretContents,
		Type: corev1.SecretTypeOpaque,
	}, nil
}

func FetchOrInitializeCARootSecret(ctx context.Context, clusterClient client.Client, namespace string, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, bool, error) {
	secret, err := fetchKubewardenCARootSecret(ctx, clusterClient, namespace)
	if err != nil && apierrors.IsNotFound(err) || isMissingSecretDataFields(secret, constants.CARootCACert, constants.CARootCACertPem, constants.CARootPrivateKeyCertName) {
		secret, err = buildCARootSecret(namespace, generateCA, pemEncodeCertificate)
		if err != nil {
			return &corev1.Secret{}, false, fmt.Errorf("cannot getch or initialize root CA secret: %w", err)
		}
		return secret, true, err
	}
	secret.ResourceVersion = ""
	if err != nil {
		return &corev1.Secret{}, false,
			fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}

	return secret, false, nil
}

func fetchKubewardenCARootSecret(ctx context.Context, clusterClient client.Client, namespace string) (*corev1.Secret, error) {
	return fetchSecret(ctx, clusterClient, namespace, constants.KubewardenCARootSecretName)
}

func fetchSecret(ctx context.Context, clusterClient client.Client, namespace string, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	if err := clusterClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		return &corev1.Secret{}, fmt.Errorf("failed to fetch secret \"%s\": [%w]", name, err)
	}
	return secret, nil
}

// Fetch or init a certificate to be used with service
func FetchOrInitializeCertificate(ctx context.Context, clusterClient client.Client, serviceName string, namespace string, secretName string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, bool, error) {
	secret, err := fetchSecret(ctx, clusterClient, namespace, secretName)
	if err != nil && apierrors.IsNotFound(err) || isMissingSecretDataFields(secret, constants.PolicyServerTLSCert, constants.PolicyServerTLSKey) {
		sans := []string{fmt.Sprintf("%s.%s.svc", serviceName, namespace)}
		secret, err = buildCertificateSecret(sans, secretName, namespace, caSecret, generateCert)
		if err != nil {
			return &corev1.Secret{}, false, fmt.Errorf("cannot fetch or initialize certificate secret: %w", err)
		}
		return secret, true, nil
	}
	if err != nil {
		return &corev1.Secret{}, false,
			fmt.Errorf("cannot fetch or initialize certificate secret: %w", err)
	}
	secret.ResourceVersion = ""

	return secret, false, nil
}

// isMissingSecretDataFields check if the given fields exists in the Data field
// of the given secret. It does not validates the content of the data fields
func isMissingSecretDataFields(secret *corev1.Secret, fields ...string) bool {
	for _, field := range fields {
		// It's not necessary to check the `StringData` field because
		// it is write-only and it will be merged with the `Data` field
		// by the API. https://pkg.go.dev/k8s.io/api/core/v1#Secret
		if _, ok := secret.Data[field]; !ok {
			return true
		}
	}
	return false
}

func buildCertificateSecret(sans []string, secretName string, namespace string, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	admissionregCA, err := extractCaFromSecret(caSecret)
	if err != nil {
		return nil, err
	}
	servingCert, servingKey, err := generateCert(
		admissionregCA.CaCert, sans,
		admissionregCA.CaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate \"%s\" certificate: %w", sans, err)
	}
	secretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels:    map[string]string{},
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}
