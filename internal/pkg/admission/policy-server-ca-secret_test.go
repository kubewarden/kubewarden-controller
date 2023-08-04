package admission

import (
	"bytes"
	"context"
	// "crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFetchOrInitializePolicyServerCARootSecret(t *testing.T) {
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
		constants.KubewardenCARootCACert:             admissionregCA.CaCert,
		constants.KubewardenCARootPemName:            caPemBytes,
		constants.KubewardenCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey),
	}

	var tests = []struct {
		name             string
		r                Reconciler
		err              error
		secretContents   map[string][]byte
		generateCACalled bool
	}{
		{"Existing CA", createReconcilerWithExistingCA(), nil, mockSecretContents, false},
		{"CA does not exist", createReconcilerWithEmptyClient(), nil, caSecretContents, true},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			secret, _, err := ttest.r.FetchOrInitializeRootCASecret(context.Background(), generateCAFunc, pemEncodeCertificateFunc)
			if diff := cmp.Diff(secret.Data, ttest.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}

			if !errors.Is(err, ttest.err) {
				t.Errorf("got %s, want %s", err, ttest.err)
			}

			if generateCACalled != ttest.generateCACalled {
				t.Errorf("got %t, want %t", generateCACalled, ttest.generateCACalled)
			}
			generateCACalled = false
		})
	}
}

func TestUpdateAllPolicyServerSecrets(t *testing.T) {
	caRoot, err := admissionregistration.GenerateCA()
	if err != nil {
		t.Fatal("cannot generate policy-server secret CA: ", err)
	}
	caPEMEncoded, err := admissionregistration.PemEncodeCertificate(caRoot.CaCert)
	if err != nil {
		t.Fatal("cannot encode policy-server secret CA: ", err)
	}
	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(caRoot.CaPrivateKey)
	secretContents := map[string][]byte{
		constants.KubewardenCARootCACert:             caRoot.CaCert,
		constants.KubewardenCARootPemName:            caPEMEncoded,
		constants.KubewardenCARootPrivateKeyCertName: caPrivateKeyBytes,
	}
	mockRootCASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.KubewardenCARootSecretName,
			Namespace: namespace,
		},
		Data: secretContents,
		Type: corev1.SecretTypeOpaque,
	}

	policyServer1 := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
		},
	}
	policyServer1.Name = "policyServer1"
	policyServerSecret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer1.NameWithPrefix(),
			Namespace: namespace,
			Labels: map[string]string{
				constants.PolicyServerLabelKey: policyServer1.Name,
			},
		},
		StringData: map[string]string{
			constants.PolicyServerTLSCert: string("policyserver1-cert"),
			constants.PolicyServerTLSKey:  string("policyserver1-key"),
		},
		Type: corev1.SecretTypeOpaque,
	}
	policyServer2 := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
		},
	}
	policyServer2.Name = "policyServer2"
	policyServerSecret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer2.NameWithPrefix(),
			Namespace: namespace,
			Labels: map[string]string{
				constants.PolicyServerLabelKey: policyServer2.Name,
			},
		},
		StringData: map[string]string{
			constants.PolicyServerTLSCert: string("policyserver2-cert"),
			constants.PolicyServerTLSKey:  string("policyserver2-key"),
		},
		Type: corev1.SecretTypeOpaque,
	}
	randomSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "random",
			Namespace: namespace,
		},
		StringData: map[string]string{
			constants.PolicyServerTLSCert: string("policyserver2-cert"),
			constants.PolicyServerTLSKey:  string("policyserver2-key"),
		},
		Type: corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: "policies.kubewarden.io", Version: "v1"}, policyServer1)
	cl := fake.NewClientBuilder().WithObjects(mockRootCASecret, policyServer1, policyServerSecret1, policyServer2, policyServerSecret2, randomSecret).Build()
	reconciler := Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
	reconciler.UpdateAllPolicyServerSecrets(context.Background(), mockRootCASecret)
	secret := corev1.Secret{}
	cl.Get(context.Background(), client.ObjectKey{Name: policyServerSecret1.Name, Namespace: namespace}, &secret)
	if cmp.Equal(secret.StringData, policyServerSecret1.StringData) {
		diff := cmp.Diff(secret.StringData, policyServerSecret2.StringData)
		t.Errorf("secret data not updated: %s", diff)
	}
	cl.Get(context.Background(), client.ObjectKey{Name: policyServerSecret2.Name, Namespace: namespace}, &secret)
	if cmp.Equal(secret.StringData, policyServerSecret2.StringData) {
		diff := cmp.Diff(secret.StringData, policyServerSecret2.StringData)
		t.Errorf("secret data not updated: %s", diff)
	}
	cl.Get(context.Background(), client.ObjectKey{Name: randomSecret.Name, Namespace: namespace}, &secret)
	if !cmp.Equal(secret.StringData, randomSecret.StringData) {
		diff := cmp.Diff(secret.StringData, policyServerSecret2.StringData)
		t.Errorf("secret with no policy server label should not be updated: %s", diff)
	}

}

const namespace = "namespace"

var mockSecretContents = map[string][]byte{"ca": []byte("secretContents")}

func createReconcilerWithExistingCA() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.KubewardenCARootSecretName,
			Namespace: namespace,
		},
		Data: mockSecretContents,
		Type: corev1.SecretTypeOpaque,
	}

	// Create a fake client to mock API calls. It will return the mock secret
	cl := fake.NewClientBuilder().WithObjects(mockSecret).Build()
	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}

var mockSecretCert = map[string]string{"cert": "certString"}

func createReconcilerWithExistingCert() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-server-policyServer",
			Namespace: namespace,
		},
		StringData: mockSecretCert,
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
