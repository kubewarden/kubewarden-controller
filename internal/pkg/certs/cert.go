package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

func GenerateCert(ca []byte,
	commonName string,
	extraSANs []string,
	caPrivateKey *rsa.PrivateKey,
) ([]byte, *rsa.PrivateKey, error) {
	caCertificate, err := x509.ParseCertificate(ca)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate serialNumber for certificate: %w", err)
	}

	// key size must be higher than 1024, otherwise the PolicyServer
	// TLS acceptor will refuse to start
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
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

	cert := x509.Certificate{
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
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&cert,
		caCertificate,
		&privateKey.PublicKey,
		caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	return certBytes, privateKey, nil
}
