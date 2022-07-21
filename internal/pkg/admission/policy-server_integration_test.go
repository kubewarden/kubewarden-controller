package admission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

const port = "8181"

func TestCAAndCertificateCreationInAHttpsServer(t *testing.T) {
	const domain = "localhost"
	const maxRetries = 10
	r := createReconcilerWithEmptyClient()
	// create CA
	caSecret, err := r.buildPolicyServerCARootSecret(admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
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
