package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type CA struct {
	CaCert       x509.Certificate
	CaCertBytes  []byte
	CaPrivateKey *rsa.PrivateKey
}

func (ca *CA) PEMEncodeCertificate() (*bytes.Buffer, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.CaCertBytes,
	})
	if err != nil {
		return nil, errors.Join(errors.New("cannot PEM encode certificate"), err)
	}
	return caPEM, nil
}

func (ca *CA) PEMEncodePrivateKey() (*bytes.Buffer, error) {
	privateKeyPEM := new(bytes.Buffer)
	err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.CaPrivateKey),
	})
	if err != nil {
		return nil, errors.Join(errors.New("cannot PEM encode private key"), err)
	}
	return privateKeyPEM, nil
}

func (ca *CA) PEMEncodePublicKey() (string, error) {
	publicKeyPEM := new(bytes.Buffer)
	publicKey, err := x509.MarshalPKIXPublicKey(&ca.CaPrivateKey.PublicKey)
	if err != nil {
		return "", errors.Join(errors.New("cannot marshal public key"), err)
	}
	err = pem.Encode(publicKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	})
	if err != nil {
		return "", errors.Join(errors.New("cannot encode public key"), err)
	}
	return publicKeyPEM.String(), nil
}

func GenerateCA() (*CA, error) {
	privateKey, err := newPrivateKey(1024)
	if err != nil {
		return nil, errors.Join(errors.New("cannot create private key"), err)
	}
	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil, errors.Join(errors.New("cannot init serial number"), err)
	}
	caCertificateTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{""},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years expiration
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caCertificateBytes, err := x509.CreateCertificate(
		rand.Reader,
		&caCertificateTemplate,
		&caCertificateTemplate,
		&privateKey.Key().PublicKey,
		privateKey.Key())
	if err != nil {
		return nil, errors.Join(errors.New("cannot create certificate"), err)
	}
	return &CA{caCertificateTemplate, caCertificateBytes, privateKey.Key()}, nil
}

// ExtractCaFromSecret generates a CA object from the given secret where the
// certificate and private key are stored
func ExtractCaFromSecret(caSecret *corev1.Secret) (*CA, error) {
	caCertBytes, hasCARootCert := caSecret.Data[corev1.TLSCertKey]
	if !hasCARootCert {
		return nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}
	caCertificateBytes, _ := pem.Decode(caCertBytes)
	if caCertificateBytes == nil {
		return nil, fmt.Errorf("failed to decode Root CA certificate")
	}
	caCert, err := x509.ParseCertificate(caCertificateBytes.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA certificate could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKeyBytes, hasCARootCert := caSecret.Data[corev1.TLSPrivateKeyKey]
	if !hasCARootCert {
		return nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}
	block, _ := pem.Decode(caPrivateKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode root ca private key")
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}

	return &CA{CaCert: *caCert, CaCertBytes: caCertificateBytes.Bytes, CaPrivateKey: caPrivateKey}, nil
}
