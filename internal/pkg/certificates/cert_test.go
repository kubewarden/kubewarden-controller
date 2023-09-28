package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCAAndCertificateCreation(t *testing.T) {
	const domain = "localhost"
	// create CA
	rootCA, err := GenerateCA()
	if err != nil {
		t.Errorf("failed create root CA: %s", err.Error())
	}
	rootCertificates := x509.NewCertPool()
	rootCAPEM, err := rootCA.PEMEncodeCertificate()
	if err != nil {
		t.Fatal("failed to PEM encode root CA certificate")
	}
	if ok := rootCertificates.AppendCertsFromPEM(rootCAPEM.Bytes()); !ok {
		t.Fatal("failed to add root ca in the cert pool")
	}

	// create cert using CA previously created
	certificatePEM, _, err := GenerateCert(rootCA.CaCertBytes, []string{domain}, rootCA.CaPrivateKey)
	if err != nil {
		t.Errorf("failed generating cert: %s", err.Error())
	}

	block, _ := pem.Decode(certificatePEM.Bytes())
	certificate, _ := x509.ParseCertificate(block.Bytes)

	verifyOptions := x509.VerifyOptions{
		DNSName: domain,
		Roots:   rootCertificates,
	}

	if _, err := certificate.Verify(verifyOptions); err != nil {
		t.Fatalf("failed to verify certificate: %q", err)
	}
}
