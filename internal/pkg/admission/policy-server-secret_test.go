package admission

import (
	"bytes"
	"context"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
)

func TestFetchOrInitializePolicyServerSecret(t *testing.T) {
	caBytes := []byte{}
	b, ca, err := admissionregistration.GenerateCA()
	generateCACalled := false

	generateCAFunc := func() ([]byte, *admissionregistration.KeyPair, error) {
		generateCACalled = true
		return b, ca, err
	}

	pemEncodeCertificateFunc := func(certificate []byte) ([]byte, error) {
		if bytes.Compare(certificate, b) != 0 {
			return nil, fmt.Errorf("certificate received should be the one returned by generateCA")
		}
		return caBytes, nil
	}

	caSecretContents := map[string]string{
		constants.PolicyServerCARootPemName:            string(caBytes),
		constants.PolicyServerCARootPrivateKeyCertName: ca.PrivateKey,
	}

	var tests = []struct {
		name             string
		r                Reconciler
		err              error
		secretContents   map[string]string
		generateCACalled bool
	}{
		{"Existing CA", createReconcilerWithExistingCA(), nil, mockSecretContents, false},
		{"CA does not exist", createReconcilerWithOutCA(), nil, caSecretContents, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret, err := test.r.fetchOrInitializePolicyServerCARootSecret(context.Background(), generateCAFunc, pemEncodeCertificateFunc)
			if diff := cmp.Diff(secret.StringData, test.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}

			if err != test.err {
				t.Errorf("got %s, want %s", err, test.err)
			}

			if generateCACalled != test.generateCACalled {
				t.Errorf("got %t, want %t", generateCACalled, test.generateCACalled)
			}
			generateCACalled = false
		})
	}

}

const namespace = "namespace"

var mockSecretContents = map[string]string{"ca": "secretContents"}

func createReconcilerWithExistingCA() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: namespace,
		},
		StringData: mockSecretContents,
		Type:       corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	cl := fake.NewClientBuilder().WithObjects(mockSecret).Build()
	return Reconciler{
		Client:                        cl,
		DeploymentsNamespace:          namespace,
		DeploymentsServiceAccountName: "",
	}
}

func createReconcilerWithOutCA() Reconciler {
	// Create a fake client to mock API calls.
	cl := fake.NewClientBuilder().WithObjects().Build()
	return Reconciler{
		Client:                        cl,
		DeploymentsNamespace:          namespace,
		DeploymentsServiceAccountName: "",
	}
}
