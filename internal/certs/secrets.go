package certs

import (
	"fmt"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
	corev1 "k8s.io/api/core/v1"
)

// Extract the CA certificate and private key from a secret.
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

// Extract the server certificate and private key from a secret.
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
