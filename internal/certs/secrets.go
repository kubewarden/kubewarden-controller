package certs

import (
	"fmt"

	"github.com/kubewarden/adm-controller/internal/constants"
	corev1 "k8s.io/api/core/v1"
)

// ExtractCARootFromSecret extracts  the CA certificate and private key from a secret.
// Both are PEM encoded.
func ExtractCARootFromSecret(caRootSecret *corev1.Secret) ([]byte, []byte, error) {
	caCert, found := caRootSecret.Data[constants.CARootCert]
	if !found {
		return nil, nil, fmt.Errorf("CA could not be extracted from secret: %s", caRootSecret.GetName())
	}
	if len(caCert) == 0 {
		return nil, nil, fmt.Errorf("CA certificate is empty in secret: %s", caRootSecret.GetName())
	}

	caPrivateKey, found := caRootSecret.Data[constants.CARootPrivateKey]
	if !found {
		return nil, nil, fmt.Errorf("CA private key bytes could not be extracted from secret: %s", caRootSecret.GetName())
	}
	if len(caPrivateKey) == 0 {
		return nil, nil, fmt.Errorf("CA private key is empty in secret: %s", caRootSecret.GetName())
	}

	return caCert, caPrivateKey, nil
}

// CABundleFromSecret returns the CA bundle of the CA root secret: the CA
// certificate, followed by the old CA certificate if the secret has one. Every
// caBundle of a webhook configuration must come from this function. The result
// is a new deep-copy slice, so a change to it does not change the secret.
func CABundleFromSecret(caRootSecret *corev1.Secret) []byte {
	caCert := caRootSecret.Data[constants.CARootCert]
	oldCACert := caRootSecret.Data[constants.OldCARootCert]

	bundle := make([]byte, 0, len(caCert)+len(oldCACert))
	bundle = append(bundle, caCert...)
	return append(bundle, oldCACert...)
}

// ExtractServerCertFromSecret extracts the server certificate and private key from a secret.
// Both are PEM encoded.
func ExtractServerCertFromSecret(serverCertSecret *corev1.Secret) ([]byte, []byte, error) {
	serverCert, found := serverCertSecret.Data[constants.ServerCert]
	if !found {
		return nil, nil, fmt.Errorf("server certificate could not be extracted from secret: %s", serverCertSecret.GetName())
	}
	if len(serverCert) == 0 {
		return nil, nil, fmt.Errorf("server certificate is empty in secret: %s", serverCertSecret.GetName())
	}

	serverPrivateKey, found := serverCertSecret.Data[constants.ServerPrivateKey]
	if !found {
		return nil, nil, fmt.Errorf("server private key could not be extracted from secret: %s", serverCertSecret.GetName())
	}
	if len(serverPrivateKey) == 0 {
		return nil, nil, fmt.Errorf("server private key is empty in secret: %s", serverCertSecret.GetName())
	}

	return serverCert, serverPrivateKey, nil
}
