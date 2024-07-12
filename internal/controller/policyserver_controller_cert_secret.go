package controller

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/certs"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// Reconcile the certificate to be used by the policy server for TLS. The
// generated certificate is signed by the CA certificate provided in the
// caSecret. The generated certificate is stored in a secret.
func (r *PolicyServerReconciler) reconcilePolicyServerCertSecret(ctx context.Context, policyServer *policiesv1.PolicyServer, caSecret *corev1.Secret) error {
	policyServerSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.DeploymentsNamespace,
			Name:      policyServer.NameWithPrefix(),
		},
	}

	_, err := controllerutil.CreateOrPatch(ctx, r.Client, policyServerSecret, func() error {
		if err := controllerutil.SetOwnerReference(policyServer, policyServerSecret, r.Client.Scheme()); err != nil {
			return errors.Join(errors.New("failed to set policy server secret owner reference"), err)
		}

		// check if secret has the required data
		_, hasTLSCert := policyServerSecret.Data[constants.PolicyServerTLSCert]
		_, hasTLSKey := policyServerSecret.Data[constants.PolicyServerTLSKey]
		if !hasTLSCert || !hasTLSKey {
			caCert, caPrivateKey, err := extractCAFromSecret(caSecret)
			if err != nil {
				return err
			}

			cert, privateKey, err := certs.GenerateCert(
				caCert,
				fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace),
				[]string{fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace)},
				caPrivateKey)
			if err != nil {
				return fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServer.NameWithPrefix(), err)
			}

			certPEM, err := certs.PEMEncodeCertificate(cert)
			if err != nil {
				return fmt.Errorf("cannot PEM encode policy-server %s certificate: %w", policyServer.NameWithPrefix(), err)
			}

			privateKeyPEM, err := certs.PEMEncodePrivateKey(privateKey)
			if err != nil {
				return fmt.Errorf("cannot PEM encode policy-server %s private key: %w", policyServer.NameWithPrefix(), err)
			}

			policyServerSecret.Type = corev1.SecretTypeOpaque
			policyServerSecret.StringData = map[string]string{
				constants.PolicyServerTLSCert: string(certPEM),
				constants.PolicyServerTLSKey:  string(privateKeyPEM),
			}
		}

		return nil
	})
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCertSecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return errors.Join(errors.New("cannot fetch or initialize Policy Server CA secret"), err)
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCertSecretReconciled),
	)

	return nil
}

// Reconcile the internal CA root secret used by the controller to sign
// the policy server certificate.
func (r *PolicyServerReconciler) reconcileInternalCARootSecret(ctx context.Context, policyServer *policiesv1.PolicyServer) (*corev1.Secret, error) {
	policyServerSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.PolicyServerCARootSecretName,
		},
	}

	_, err := controllerutil.CreateOrPatch(ctx, r.Client, policyServerSecret, func() error {
		_, hasCARootCert := policyServerSecret.Data[constants.PolicyServerCARootCACert]
		_, hasCARootPem := policyServerSecret.Data[constants.PolicyServerCARootPemName]
		_, hasCARootPrivateKey := policyServerSecret.Data[constants.PolicyServerCARootPrivateKeyCertName]

		if !hasCARootCert || !hasCARootPem || !hasCARootPrivateKey {
			return createInternalCASecret(policyServerSecret)
		}
		return nil
	})
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.CARootSecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return nil, errors.Join(errors.New("cannot fetch or initialize Policy Server CA secret"), err)
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.CARootSecretReconciled),
	)

	return policyServerSecret, nil
}

// Extract the CA certificate and private key from the secret storing the CA data
// used in the policy server certificate generation.
func extractCAFromSecret(caSecret *corev1.Secret) ([]byte, *rsa.PrivateKey, error) {
	caCert, ok := caSecret.Data[constants.PolicyServerCARootCACert]
	if !ok {
		return nil, nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}

	privateKeyBytes, ok := caSecret.Data[constants.PolicyServerCARootPrivateKeyCertName]
	if !ok {
		return nil, nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}

	return caCert, privateKey, nil
}

// Create the internal CA root secret used by the controller to sign
// the policy server certificates. The created CA is stored in the secret
// provided as argument.
func createInternalCASecret(policyServerSecret *corev1.Secret) error {
	caCert, privateKey, err := certs.GenerateCA()
	if err != nil {
		return fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}

	caCertPEM, err := certs.PEMEncodeCertificate(caCert)
	if err != nil {
		return fmt.Errorf("cannot PEM encode policy-server secret CA certificate: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	secretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             caCert,
		constants.PolicyServerCARootPemName:            caCertPEM,
		constants.PolicyServerCARootPrivateKeyCertName: privateKeyBytes,
	}
	policyServerSecret.Type = corev1.SecretTypeOpaque
	policyServerSecret.Data = secretContents

	return nil
}
