package admission

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/certificates"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFetchOrInitializePolicyServerCARootSecret(t *testing.T) {
	admissionregCA, _ := certificates.GenerateCA()
	certificatePEMEncoded, err := admissionregCA.PEMEncodeCertificate()
	if err != nil {
		t.Fatalf("unable to PEM encode CA certificate")
	}

	caSecretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             admissionregCA.CaCertBytes,
		constants.PolicyServerCARootPemName:            certificatePEMEncoded.Bytes(),
		constants.PolicyServerCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey),
	}

	var tests = []struct {
		name           string
		r              Reconciler
		secretContents map[string][]byte
	}{
		{"Existing CA", createReconcilerWithExistingCA(caSecretContents), caSecretContents},
		{"CA does not exist", createReconcilerWithEmptyClient(), nil},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			secret, err := ttest.r.fetchOrInitializePolicyServerCARootSecret(context.Background())
			if err != nil {
				t.Fatalf("Unexpected error: %q", err)
			}
			if ttest.secretContents == nil {
				// no expected secret context. Thus, the function should create the data
				err := ttest.r.Client.Get(
					context.TODO(),
					client.ObjectKey{
						Namespace: ttest.r.DeploymentsNamespace,
						Name:      constants.PolicyServerCARootSecretName},
					&corev1.Secret{})
				if err == nil {
					t.Fatal("Get should not return object. It should fail")
				}
				if err != nil && !apierrors.IsNotFound(err) {
					t.Fatalf("Unexpected error while checking for secret: %q", err)
				}
				if secret.Name != constants.PolicyServerCARootSecretName {
					t.Errorf("Invalid CA secret name: %s", secret.Name)
				}
				for _, dataField := range []string{constants.PolicyServerCARootCACert, constants.PolicyServerCARootPemName, constants.PolicyServerCARootPrivateKeyCertName} {
					if _, ok := secret.Data[dataField]; !ok {
						t.Errorf("Missing data field: %s", dataField)
					}
				}
			} else {
				if diff := cmp.Diff(secret.Data, ttest.secretContents); diff != "" {
					t.Errorf("got an unexpected secret, diff %s", diff)
				}
			}
		})
	}
}

func TestFetchOrInitializePolicyServerSecret(t *testing.T) {
	servingCert := []byte{1}
	servingKey := []byte{2}
	admissionregCA, _ := certificates.GenerateCA()
	caSecret := &corev1.Secret{
		Data: map[string][]byte{
			constants.PolicyServerCARootCACert:             admissionregCA.CaCertBytes,
			constants.PolicyServerCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey),
		},
	}

	caSecretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}

	var tests = []struct {
		name           string
		r              Reconciler
		secretContents map[string]string
	}{
		{"Existing cert", createReconcilerWithExistingCert(caSecretContents), caSecretContents},
		{"cert does not exist", createReconcilerWithEmptyClient(), nil},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			policyServerName := "policyServer"
			secret, err := ttest.r.fetchOrInitializePolicyServerCASecret(context.Background(), policyServerName, caSecret)
			if err != nil {
				t.Fatalf("Unexpected error: %q", err)
			}
			if ttest.secretContents == nil {
				// no expected secret context. Thus, the function should create the data
				err := ttest.r.Client.Get(
					context.TODO(),
					client.ObjectKey{
						Namespace: ttest.r.DeploymentsNamespace,
						Name:      policyServerName},
					&corev1.Secret{})
				if err == nil {
					t.Fatal("Get should not return object. It should fail")
				}
				if err != nil && !apierrors.IsNotFound(err) {
					t.Fatalf("Unexpected error while checking for secret: %q", err)
				}
				if secret.Name != policyServerName {
					t.Errorf("Invalid secret name: %s", secret.Name)
				}
				for _, dataField := range []string{constants.PolicyServerTLSCert, constants.PolicyServerTLSKey} {
					if _, ok := secret.StringData[dataField]; !ok {
						t.Errorf("Missing data field: %s", dataField)
					}
				}
			} else {
				if diff := cmp.Diff(secret.StringData, ttest.secretContents); diff != "" {
					t.Errorf("got an unexpected secret, diff %s", diff)
				}
			}
		})
	}
}

const namespace = "namespace"

func createReconcilerWithExistingCA(caSecretContents map[string][]byte) Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: namespace,
		},
		Data: caSecretContents,
		Type: corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	cl := fake.NewClientBuilder().WithObjects(mockSecret).Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}

func createReconcilerWithExistingCert(secretCert map[string]string) Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policyServer",
			Namespace: namespace,
		},
		StringData: secretCert,
		Type:       corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	cl := fake.NewClientBuilder().WithObjects(mockSecret).Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}

func createReconcilerWithEmptyClient() Reconciler {
	// Create a fake client to mock API calls.
	cl := fake.NewClientBuilder().Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}
