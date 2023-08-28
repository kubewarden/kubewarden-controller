package admission

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFetchOrInitializePolicyServerSecret(t *testing.T) {
	generateCertCalled := false
	servingCert := []byte{1}
	servingKey := []byte{2}
	admissionregCA, _ := admissionregistration.GenerateCA()
	caSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCACert: admissionregCA.CaCert, constants.CARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey)}}

	//nolint:unparam
	generateCertFunc := func(ca []byte, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error) {
		generateCertCalled = true
		return servingCert, servingKey, nil
	}

	caSecretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}

	var tests = []struct {
		name               string
		r                  Reconciler
		err                error
		secretContents     map[string]string
		generateCertCalled bool
	}{
		{"Existing cert", createReconcilerWithExistingCert(), nil, mockSecretCert, false},
		{"cert does not exist", createReconcilerWithEmptyClient(), nil, caSecretContents, true},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			secret, err := ttest.r.fetchOrInitializePolicyServerCASecret(context.Background(), "policyServer", "policyServer", caSecret, generateCertFunc)
			if diff := cmp.Diff(secret.StringData, ttest.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}

			if !errors.Is(err, ttest.err) {
				t.Errorf("got %s, want %s", err, ttest.err)
			}

			if generateCertCalled != ttest.generateCertCalled {
				t.Errorf("got %t, want %t", generateCertCalled, ttest.generateCertCalled)
			}
			if generateCertCalled {
				if policyServerName, hasLabel := secret.Labels[constants.PolicyServerLabelKey]; !hasLabel || policyServerName != "policyServer" {
					t.Errorf("invalid %s label: got %t, want %t", constants.PolicyServerLabelKey, generateCertCalled, ttest.generateCertCalled)
				}
			}
			generateCertCalled = false
		})
	}
}

func TestFetchOrInitializeCARootSecret(t *testing.T) {
	caPemBytes := []byte{}
	admissionregCA, err := admissionregistration.GenerateCA()
	generateCACalled := false

	//nolint: wrapcheck
	generateCAFunc := func() (*admissionregistration.CA, error) {
		generateCACalled = true
		return admissionregCA, err
	}

	pemEncodeCertificateFunc := func(certificate []byte) ([]byte, error) {
		if !bytes.Equal(certificate, admissionregCA.CaCert) {
			return nil, fmt.Errorf("certificate received should be the one returned by generateCA")
		}
		return caPemBytes, nil
	}

	caSecretContents := map[string][]byte{
		constants.CARootCACert:             admissionregCA.CaCert,
		constants.CARootCACertPem:          caPemBytes,
		constants.CARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey),
	}

	var tests = []struct {
		name             string
		client           client.Client
		err              error
		secretContents   map[string][]byte
		generateCACalled bool
	}{
		{"Existing CA", fake.NewClientBuilder().WithObjects(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.KubewardenCARootSecretName,
				Namespace: namespace,
			},
			Data: caSecretContents,
			Type: corev1.SecretTypeOpaque,
		}).Build(), nil, caSecretContents, false},
		{"CA does not exist", fake.NewClientBuilder().WithObjects().Build(), nil, caSecretContents, true},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			generateCACalled = false

			secret, initialized, err := FetchOrInitializeCARootSecret(context.Background(), ttest.client, namespace, generateCAFunc, pemEncodeCertificateFunc)

			if generateCACalled != ttest.generateCACalled {
				t.Fatalf("got %t, want %t", generateCACalled, ttest.generateCACalled)
			}
			if initialized != ttest.generateCACalled {
				t.Fatalf("root CA should be initialized")
			}
			if !errors.Is(err, ttest.err) {
				t.Fatalf("Unexpected error: %s.  Expected %s", err, ttest.err)
			}

			if diff := cmp.Diff(secret.Data, ttest.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}
		})
	}
}

func TestFetchOrInitializeCertificate(t *testing.T) {
	generateCertCalled := false
	servingCert := []byte{1}
	servingKey := []byte{2}
	admissionregCA, _ := admissionregistration.GenerateCA()
	caSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCACert: admissionregCA.CaCert, constants.CARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey)}}

	//nolint:unparam
	generateCertFunc := func(ca []byte, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error) {
		generateCertCalled = true
		return servingCert, servingKey, nil
	}

	caSecretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}
	caSecretContentsData := map[string][]byte{
		constants.PolicyServerTLSCert: servingCert,
		constants.PolicyServerTLSKey:  servingKey,
	}

	var tests = []struct {
		name               string
		client             client.Client
		err                error
		secretContents     map[string]string
		generateCertCalled bool
		serviceName        string
		secretName         string
	}{
		{"Existing cert", fake.NewClientBuilder().WithObjects(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testingSecretName",
				Namespace: namespace,
			},
			StringData: mockSecretCert,
			Data:       caSecretContentsData,
			Type:       corev1.SecretTypeOpaque,
		}).Build(), nil, mockSecretCert, false, "policyServer", "testingSecretName"},
		{"cert does not exist", fake.NewClientBuilder().WithObjects().Build(), nil, caSecretContents, true, "policyServer", "testingSecretName"},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			generateCertCalled = false

			secret, initialized, err := FetchOrInitializeCertificate(context.Background(), ttest.client, ttest.serviceName, namespace, ttest.secretName, caSecret, generateCertFunc)

			if generateCertCalled != ttest.generateCertCalled {
				t.Fatalf("got %t, want %t", generateCertCalled, ttest.generateCertCalled)
			}

			if initialized != ttest.generateCertCalled {
				t.Fatalf("initialized flag invalid value")
			}

			if !errors.Is(err, ttest.err) {
				t.Fatalf("got %s, want %s", err, ttest.err)
			}

			if secret.Name != ttest.secretName {
				t.Errorf("invalid secret name. Got %s, want %s", secret.Name, ttest.secretName)
			}

			if diff := cmp.Diff(secret.StringData, ttest.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}
		})
	}
}

func TestFetchCARootSecret(t *testing.T) {
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.KubewardenCARootSecretName,
			Namespace: namespace,
		},
		Data: mockSecretContents,
		Type: corev1.SecretTypeOpaque,
	}
	var tests = []struct {
		name           string
		client         client.Client
		expectedSecret *corev1.Secret
		validateError  func(error) bool
	}{
		{"Existing CA", fake.NewClientBuilder().WithObjects(&secret).Build(), &secret, func(err error) bool { return err == nil }},
		{"CA does not exist", fake.NewClientBuilder().WithObjects().Build(), &corev1.Secret{}, apierrors.IsNotFound},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			secret, err := fetchKubewardenCARootSecret(context.Background(), ttest.client, namespace)

			if !ttest.validateError(err) {
				t.Fatalf("Unexpected error: %s", err)
			}

			if diff := cmp.Diff(ttest.expectedSecret.Data, secret.Data); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}
		})
	}
}

func TestIsMissingSecretDataFields(t *testing.T) {
	var tests = []struct {
		name                        string
		secret                      *corev1.Secret
		missingFields               []string
		secretIsMissingRequiredData bool
	}{
		{"Missing all required data", &corev1.Secret{}, []string{constants.CARootCACert, constants.CARootCACertPem, constants.CARootPrivateKeyCertName}, true},

		{fmt.Sprintf("Missing %s field", constants.CARootCACert), &corev1.Secret{
			Data: map[string][]byte{
				constants.CARootCACertPem:          []byte(constants.CARootCACertPem),
				constants.CARootPrivateKeyCertName: []byte(constants.CARootPrivateKeyCertName),
			},
		}, []string{constants.CARootCACert}, true},

		{fmt.Sprintf("Missing %s field", constants.CARootCACertPem), &corev1.Secret{
			Data: map[string][]byte{
				constants.CARootCACert:             []byte(constants.CARootCACert),
				constants.CARootPrivateKeyCertName: []byte(constants.CARootPrivateKeyCertName),
			}}, []string{constants.CARootCACertPem}, true},

		{fmt.Sprintf("Missing %s field", constants.CARootPrivateKeyCertName), &corev1.Secret{
			Data: map[string][]byte{
				constants.CARootCACert:    []byte(constants.CARootCACert),
				constants.CARootCACertPem: []byte(constants.CARootCACertPem),
			}}, []string{constants.CARootPrivateKeyCertName}, true},

		{fmt.Sprintf("Missing %s field", constants.PolicyServerTLSCert), &corev1.Secret{
			Data: map[string][]byte{
				constants.PolicyServerTLSKey: []byte(constants.PolicyServerTLSKey),
			},
		}, []string{constants.PolicyServerTLSCert}, true},

		{fmt.Sprintf("Missing %s field", constants.PolicyServerTLSKey), &corev1.Secret{
			Data: map[string][]byte{
				constants.PolicyServerTLSCert: []byte(constants.PolicyServerTLSCert),
			},
		}, []string{constants.PolicyServerTLSKey}, true},

		{"All required data define", &corev1.Secret{
			Data: map[string][]byte{
				constants.CARootCACert:             []byte(constants.CARootCACert),
				constants.CARootCACertPem:          []byte(constants.CARootCACertPem),
				constants.CARootPrivateKeyCertName: []byte(constants.CARootPrivateKeyCertName),
			},
		}, []string{constants.CARootCACert, constants.CARootCACertPem, constants.CARootPrivateKeyCertName}, false},
		{"Only a subset required", &corev1.Secret{
			Data: map[string][]byte{
				constants.CARootCACert:             []byte(constants.CARootCACert),
				constants.CARootCACertPem:          []byte(constants.CARootCACertPem),
				constants.CARootPrivateKeyCertName: []byte(constants.CARootPrivateKeyCertName),
			},
		}, []string{constants.CARootPrivateKeyCertName, constants.CARootCACertPem}, false},
	}
	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			isMissingCertData := isMissingSecretDataFields(ttest.secret, ttest.missingFields...)
			if ttest.secretIsMissingRequiredData != isMissingCertData {
				t.Errorf("secret is missing some field. Required fields %s, fields defined %s", ttest.missingFields, ttest.secret.Data)
			}
		})
	}
}

const namespace = "namespace"

var mockSecretContents = map[string][]byte{"ca": []byte("secretContents")}

var mockSecretCert = map[string]string{constants.PolicyServerTLSCert: "certString", constants.PolicyServerTLSKey: "key"}
var mockSecretCertData = map[string][]byte{constants.PolicyServerTLSCert: []byte("certString"), constants.PolicyServerTLSKey: []byte("key")}

func createReconcilerWithExistingCert() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policyServer",
			Namespace: namespace,
		},
		StringData: mockSecretCert,
		Data:       mockSecretCertData,
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
	cl := fake.NewClientBuilder().WithObjects().Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}
