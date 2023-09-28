package certificates

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
)

func TestCAExtractionFromSecret(t *testing.T) {
	rootCA, err := GenerateCA()
	if err != nil {
		t.Errorf("failed create root CA: %s", err.Error())
	}
	rootCASecret := &corev1.Secret{
		Type: corev1.SecretTypeTLS,
	}
	certificatePEMEncoded, err := rootCA.PEMEncodeCertificate()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEMEncoded, err := rootCA.PEMEncodePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootCASecret.Data = map[string][]byte{
		corev1.TLSCertKey:       certificatePEMEncoded.Bytes(),
		corev1.TLSPrivateKeyKey: privateKeyPEMEncoded.Bytes(),
	}
	extractedCA, err := ExtractCaFromSecret(rootCASecret)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(rootCA.CaCertBytes, extractedCA.CaCertBytes); diff != "" {
		t.Errorf("invalid CaCertBytes: %s", diff)
	}
	if !rootCA.CaPrivateKey.Equal(extractedCA.CaPrivateKey) {
		t.Errorf("invalid private keys")
	}
}
