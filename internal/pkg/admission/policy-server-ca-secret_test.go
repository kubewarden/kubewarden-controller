package admission

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const port = "8181"

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
			return nil, errors.New("certificate received should be the one returned by generateCA")
		}
		return caPemBytes, nil
	}

	caSecretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             admissionregCA.CaCert,
		constants.PolicyServerCARootPemName:            caPemBytes,
		constants.PolicyServerCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey),
	}

	var tests = []struct {
		name             string
		r                Reconciler
		err              error
		secretContents   map[string][]byte
		generateCACalled bool
	}{
		{"Existing CA", createReconcilerWithExistingCA(), nil, mockRootCASecretContents, false},
		{"CA does not exist", newReconciler(nil, false, false), nil, caSecretContents, true},
	}

	for _, ttest := range tests {
		t.Run(ttest.name, func(t *testing.T) {
			policyServer := &policiesv1.PolicyServer{}
			secret, err := ttest.r.fetchOrInitializePolicyServerCARootSecret(context.Background(), policyServer, generateCAFunc, pemEncodeCertificateFunc)
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

func TestFetchOrInitializePolicyServerSecret(t *testing.T) {
	generateCertCalled := false
	servingCert := []byte{1}
	servingKey := []byte{2}
	admissionregCA, _ := admissionregistration.GenerateCA()
	caSecret := &corev1.Secret{Data: map[string][]byte{constants.PolicyServerCARootCACert: admissionregCA.CaCert, constants.PolicyServerCARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey)}}

	//nolint:unparam,revive
	generateCertFunc := func(_ca []byte, _commonName string, _extraSANs []string, _CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error) {
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
		{"cert does not exist", newReconciler(nil, false, false), nil, caSecretContents, true},
	}

	for _, ttest := range tests {
		t.Run(ttest.name, func(t *testing.T) {
			policyServer := &policiesv1.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "policyServer",
				},
			}
			err := ttest.r.fetchOrInitializePolicyServerCASecret(context.Background(), policyServer, caSecret, generateCertFunc)

			secret := &corev1.Secret{}
			_ = ttest.r.Client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: policyServer.NameWithPrefix()}, secret)

			if diff := cmp.Diff(secret.StringData, ttest.secretContents); diff != "" {
				t.Errorf("got an unexpected secret, diff %s", diff)
			}

			if !errors.Is(err, ttest.err) {
				t.Errorf("got %s, want %s", err, ttest.err)
			}

			if generateCertCalled != ttest.generateCertCalled {
				t.Errorf("got %t, want %t", generateCertCalled, ttest.generateCertCalled)
			}
			generateCertCalled = false
		})
	}
}

func TestCAAndCertificateCreationInAHttpsServer(t *testing.T) {
	const domain = "localhost"
	const maxRetries = 10
	caSecret := &corev1.Secret{}
	// create CA
	err := updateSecretCA(caSecret, admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
	if err != nil {
		t.Errorf("CA secret could not be created: %s", err.Error())
	}
	admissionregCA, err := extractCaFromSecret(caSecret)
	if err != nil {
		t.Errorf("CA could not be extracted from secret: %s", err.Error())
	}
	// create cert using CA previously created
	servingCert, servingKey, err := admissionregistration.GenerateCert(
		admissionregCA.CaCert,
		domain,
		[]string{domain},
		admissionregCA.CaPrivateKey)
	if err != nil {
		t.Errorf("failed generating cert: %s", err.Error())
	}

	var server http.Server
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	// create https server with the certificates created
	go func() {
		cert, err := tls.X509KeyPair(servingCert, servingKey)
		if err != nil {
			t.Errorf("could not load cert: %s", err.Error())
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server = http.Server{
			Addr:              ":" + port,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: time.Second,
		}
		waitGroup.Done()
		_ = server.ListenAndServeTLS("", "")
	}()

	// wait for https server to be ready to avoid race conditions
	waitGroup.Wait()
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caSecret.Data[constants.PolicyServerCARootPemName])
	retries := 0
	var conn *tls.Conn
	for retries < maxRetries {
		// test ssl handshake using the ca pem
		conn, err = tls.Dial("tcp", domain+":"+port, &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12})
		if err == nil || !isConnectionRefusedError(err) {
			break
		}
		// wait 50 millisecond and retry to avoid race conditions as server might still not be ready
		time.Sleep(50 * time.Millisecond)
		retries++
	}
	if err != nil {
		t.Errorf("error when connecting to the https server : %s", err.Error())
	}
	err = conn.Close()
	if err != nil {
		t.Errorf("error when closing connection : %s", err.Error())
	}
	err = server.Shutdown(context.Background())
	if err != nil {
		t.Errorf("error when shutting down https server : %s", err.Error())
	}
}

func isConnectionRefusedError(err error) bool {
	return err.Error() == "dial tcp [::1]:"+port+": connect: connection refused"
}

const namespace = "namespace"

var mockRootCASecretContents = map[string][]byte{
	constants.PolicyServerCARootCACert:             []byte("caCert"),
	constants.PolicyServerCARootPemName:            []byte("caPem"),
	constants.PolicyServerCARootPrivateKeyCertName: []byte("caPrivateKey"),
}

var mockRootCASecretCert = map[string]string{
	constants.PolicyServerCARootCACert:             "caCert",
	constants.PolicyServerCARootPemName:            "caPem",
	constants.PolicyServerCARootPrivateKeyCertName: "caPrivateKey",
}

func createReconcilerWithExistingCA() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerCARootSecretName,
			Namespace: namespace,
		},
		Data:       mockRootCASecretContents,
		StringData: mockRootCASecretCert,
		Type:       corev1.SecretTypeOpaque,
	}

	return newReconciler([]client.Object{mockSecret}, false, false)
}

var mockSecretContents = map[string][]byte{
	constants.PolicyServerTLSCert: []byte("tlsCert"),
	constants.PolicyServerTLSKey:  []byte("tlsKey"),
}

var mockSecretCert = map[string]string{
	constants.PolicyServerTLSCert: "tlsCert",
	constants.PolicyServerTLSKey:  "tlsKey",
}

func createReconcilerWithExistingCert() Reconciler {
	mockSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-server-policyServer",
			Namespace: namespace,
		},
		Data:       mockSecretContents,
		StringData: mockSecretCert,
		Type:       corev1.SecretTypeOpaque,
	}

	return newReconciler([]client.Object{mockSecret}, false, false)
}
