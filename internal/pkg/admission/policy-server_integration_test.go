package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"net/http"
	"sync"
	"testing"
)

func TestCAAndCertificateCreationInAHttpsServer(t *testing.T) {
	const domain = "localhost"
	r := createReconcilerWithEmptyClient()
	// create CA
	caSecret, err := r.buildPolicyServerCARootSecret(admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
	if err != nil {
		t.Errorf("CA secret could not be created: %s", err.Error())
	}
	ca, err := extractCaFromSecret(caSecret)
	if err != nil {
		t.Errorf("CA could not be extracted from secret: %s", err.Error())
	}
	// create cert using CA previously created
	servingCert, servingKey, err := admissionregistration.GenerateCert(
		ca.CaCert,
		domain,
		[]string{domain},
		ca.CaPrivateKey)

	var server http.Server
	var wg sync.WaitGroup
	wg.Add(1)

	// create https server with the certificates created
	go func() {
		cert, err := tls.X509KeyPair(servingCert, servingKey)
		if err != nil {
			t.Errorf("could not load cert: %s", err.Error())
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		server = http.Server{
			Addr:      ":8080",
			TLSConfig: tlsConfig,
		}
		wg.Done()
		server.ListenAndServeTLS("", "")
	}()

	//wait for https server to be ready to avoid race conditions
	wg.Wait()
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caSecret.Data[constants.PolicyServerCARootPemName])
	//test ssl handshake using the ca pem
	conn, err := tls.Dial("tcp", domain+":8080", &tls.Config{RootCAs: rootCAs})
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
