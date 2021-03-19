package admissionregistration

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func GenerateCA() ([]byte, *KeyPair, error) {
	privateKey, err := newPrivateKey(1024)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create private key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot init serial number: %w", err)
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
		NotAfter:              time.Now().AddDate(10, 0, 0),
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
		return []byte{}, nil, fmt.Errorf("cannot create certificate: %w", err)
	}
	return caCertificateBytes, privateKey, nil
}
