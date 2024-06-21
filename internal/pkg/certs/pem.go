package certs

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func PEMEncodeCertificate(certificate []byte) ([]byte, error) {
	certificatePEM := new(bytes.Buffer)

	err := pem.Encode(certificatePEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("PEM encode failure: %w", err)
	}

	return certificatePEM.Bytes(), nil
}

func PEMEncodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := new(bytes.Buffer)

	err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("PEM encode failure: %w", err)
	}

	return privateKeyPEM.Bytes(), nil
}
