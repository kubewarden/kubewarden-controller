package admission

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type generateCAFunc = func() (*admissionregistration.CA, error)
type pemEncodeCertificateFunc = func(certificate []byte) ([]byte, error)
type generateCertFunc = func(ca []byte, commonName string, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error)

func (r *Reconciler) fetchOrInitializePolicyServerCASecret(ctx context.Context, policyServer *policiesv1.PolicyServer, caSecret *corev1.Secret, generateCert generateCertFunc) error {
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
			admissionregCA, err := extractCaFromSecret(caSecret)
			if err != nil {
				return err
			}
			servingCert, servingKey, err := generateCert(
				admissionregCA.CaCert,
				fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace),
				[]string{fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace)},
				admissionregCA.CaPrivateKey)
			if err != nil {
				return fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServer.NameWithPrefix(), err)
			}
			policyServerSecret.Type = corev1.SecretTypeOpaque
			policyServerSecret.StringData = map[string]string{
				constants.PolicyServerTLSCert: string(servingCert),
				constants.PolicyServerTLSKey:  string(servingKey),
			}
		}

		return nil
	})
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCASecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return errors.Join(errors.New("cannot fetch or initialize Policy Server CA secret"), err)
	}
	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCASecretReconciled),
	)

	return nil
}

func extractCaFromSecret(caSecret *corev1.Secret) (*admissionregistration.CA, error) {
	caCert, ok := caSecret.Data[constants.PolicyServerCARootCACert]
	if !ok {
		return nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}
	caPrivateKeyBytes, ok := caSecret.Data[constants.PolicyServerCARootPrivateKeyCertName]
	if !ok {
		return nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}
	return &admissionregistration.CA{CaCert: caCert, CaPrivateKey: caPrivateKey}, nil
}

func (r *Reconciler) fetchOrInitializePolicyServerCARootSecret(ctx context.Context, policyServer *policiesv1.PolicyServer, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
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
			return updateSecretCA(policyServerSecret, generateCA, pemEncodeCertificate)
		}
		return nil
	})
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCARootSecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return nil, errors.Join(errors.New("cannot fetch or initialize Policy Server CA secret"), err)
	}
	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCARootSecretReconciled),
	)
	return policyServerSecret, nil
}

func updateSecretCA(policyServerSecret *corev1.Secret, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) error {
	caRoot, err := generateCA()
	if err != nil {
		return fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}
	caPEMEncoded, err := pemEncodeCertificate(caRoot.CaCert)
	if err != nil {
		return fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}
	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(caRoot.CaPrivateKey)
	secretContents := map[string][]byte{
		constants.PolicyServerCARootCACert:             caRoot.CaCert,
		constants.PolicyServerCARootPemName:            caPEMEncoded,
		constants.PolicyServerCARootPrivateKeyCertName: caPrivateKeyBytes,
	}
	policyServerSecret.Type = corev1.SecretTypeOpaque
	policyServerSecret.Data = secretContents
	return nil
}
