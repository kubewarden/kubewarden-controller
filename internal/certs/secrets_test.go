package certs

import (
	"bytes"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubewarden/adm-controller/internal/constants"
)

func TestCABundleFromSecret(t *testing.T) {
	caCert := []byte("-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n")
	oldCACert := []byte("-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n")

	tests := []struct {
		name     string
		data     map[string][]byte
		expected []byte
	}{
		{
			name:     "the CA certificate alone when there is no old CA certificate",
			data:     map[string][]byte{constants.CARootCert: caCert},
			expected: caCert,
		},
		{
			name:     "the CA certificate followed by the old CA certificate",
			data:     map[string][]byte{constants.CARootCert: caCert, constants.OldCARootCert: oldCACert},
			expected: append(append([]byte{}, caCert...), oldCACert...),
		},
		{
			name:     "the CA certificate alone when the old CA certificate is empty",
			data:     map[string][]byte{constants.CARootCert: caCert, constants.OldCARootCert: {}},
			expected: caCert,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{Data: tc.data}

			bundle := CABundleFromSecret(secret)

			if !bytes.Equal(bundle, tc.expected) {
				t.Fatalf("expected bundle %q, got %q", tc.expected, bundle)
			}
		})
	}
}
