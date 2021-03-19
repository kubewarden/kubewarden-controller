package admissionregistration

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

func GenerateCert(ca []byte, commonName string, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error) {
	caCertificate, err := x509.ParseCertificate(ca)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate serialNumber for cartificate: %w", err)
	}

	// key size must be higher than 1024, otherwise the PolicyServer
	// TLS acceptor will refuse to start
	servingPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate private key: %w", err)
	}

	sansHosts := []string{}
	sansIps := []net.IP{}

	for _, san := range extraSANs {
		sanIP := net.ParseIP(san)
		if sanIP == nil {
			sansHosts = append(sansHosts, san)
		} else {
			sansIps = append(sansIps, sanIP)
		}
	}

	newCertificate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    commonName,
			Organization:  []string{""},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		DNSNames:     sansHosts,
		IPAddresses:  sansIps,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	servingCert, err := x509.CreateCertificate(
		rand.Reader,
		&newCertificate,
		caCertificate,
		&servingPrivateKey.PublicKey,
		CAPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}
	servingCertPEM, err := PemEncodeCertificate(servingCert)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode certificate to PEM format: %w", err)
	}
	servingPrivateKeyPKCS1 := x509.MarshalPKCS1PrivateKey(servingPrivateKey)
	servingPrivateKeyPEM, err := pemEncodePrivateKey(servingPrivateKeyPKCS1)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode private key to PEM format: %w", err)
	}
	return servingCertPEM, servingPrivateKeyPEM, nil
}

func PemEncodeCertificate(certificate []byte) ([]byte, error) {
	certificatePEM := new(bytes.Buffer)
	err := pem.Encode(certificatePEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})
	return certificatePEM.Bytes(), fmt.Errorf("PEM encode failure: %w", err)
}

func pemEncodePrivateKey(privateKey []byte) ([]byte, error) {
	privateKeyPEM := new(bytes.Buffer)
	err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKey,
	})

	return privateKeyPEM.Bytes(), fmt.Errorf("PEM encode failure: %w", err)
}
