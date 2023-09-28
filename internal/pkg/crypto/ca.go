package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

type CA struct {
	CaCert       x509.Certificate
	CaCertBytes  []byte
	CaPrivateKey *rsa.PrivateKey
}

func (ca *CA) PEMEncodeCertificate() (string, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.CaCertBytes,
	})
	if err != nil {
		return "", errors.Join(errors.New("cannot PEM encode certificate"), err)
	}
	return caPEM.String(), nil
}

func (ca *CA) PEMEncodePrivateKey() (string, error) {
	privateKeyPEM := new(bytes.Buffer)
	err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.CaPrivateKey),
	})
	if err != nil {
		return "", errors.Join(errors.New("cannot PEM encode private key"), err)
	}
	return privateKeyPEM.String(), nil
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
	caCertificate := x509.Certificate{
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
		&caCertificate,
		&caCertificate,
		&privateKey.Key().PublicKey,
		privateKey.Key())
	if err != nil {
		return nil, errors.Join(errors.New("cannot create certificate"), err)
	}
	return &CA{caCertificate, caCertificateBytes, privateKey.Key()}, nil
}
