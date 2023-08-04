package admission

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type generateCAFunc = func() (*admissionregistration.CA, error)
type pemEncodeCertificateFunc = func(certificate []byte) ([]byte, error)
type generateCertFunc = func(ca []byte, commonName string, extraSANs []string, CAPrivateKey *rsa.PrivateKey) ([]byte, []byte, error)

// reconcileCASecret reconcile the given secret.
// It updates the secret if it already exists. Otherwise, it creates the secret.
func (r *Reconciler) reconcileCASecret(ctx context.Context, secret *corev1.Secret) error {
	err := r.Client.Create(ctx, secret)
	// if the secret already exists, update it. Therefore, other resources
	// using it does not need to be restarted.
	if apierrors.IsAlreadyExists(err) {
		err = r.Client.Update(ctx, secret)
	}
	if err == nil {
		return nil
	}
	return fmt.Errorf("error reconciling policy-server CA Secret: %w", err)
}

// fetchPolicyServerCASecret gets the CA secret for the given policyServer
func (r *Reconciler) fetchPolicyServerCASecret(
	ctx context.Context,
	policyServer *policiesv1.PolicyServer,
) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      policyServer.NameWithPrefix()},
		&policyServerSecret)
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}

	policyServerSecret.ResourceVersion = ""

	return &policyServerSecret, nil
}

// initializePolicyServerCASecret creates the secret object to be used as policy server CA
//
// caSecret is the root CA secret used in the secret generation
//
// generateCA is a function used to generate the secret CA
func (r *Reconciler) initializePolicyServerCASecret(
	policyServer *policiesv1.PolicyServer,
	caSecret *corev1.Secret,
	generateCert generateCertFunc,
) (*corev1.Secret, error) {
	secret, err := r.buildPolicyServerCASecret(policyServer, caSecret, generateCert)
	if err != nil {
		return secret, fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}
	return secret, nil
}

// buildPolicyServerCASecret build the secret object to be used as policy
// server CA.
//
// caSecret is the root CA secret to be used to generate the policy server CA.
//
// generateCA is a function used to generate the secret CA and
// pemEncodeCertificateFunc is the function used to encode the root ca cert
func (r *Reconciler) buildPolicyServerCASecret(policyServer *policiesv1.PolicyServer, caSecret *corev1.Secret, generateCert generateCertFunc) (*corev1.Secret, error) {
	admissionregCA, err := extractCaFromSecret(caSecret)
	if err != nil {
		return nil, err
	}
	servingCert, servingKey, err := generateCert(
		admissionregCA.CaCert,
		fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace),
		[]string{fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace)},
		admissionregCA.CaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServer.NameWithPrefix(), err)
	}
	secretContents := map[string]string{
		constants.PolicyServerTLSCert: string(servingCert),
		constants.PolicyServerTLSKey:  string(servingKey),
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
			Labels: map[string]string{
				constants.PolicyServerLabelKey: policyServer.Name,
			},
		},
		StringData: secretContents,
		Type:       corev1.SecretTypeOpaque,
	}, nil
}

func extractCaFromSecret(caSecret *corev1.Secret) (*admissionregistration.CA, error) {
	caCert, ok := caSecret.Data[constants.KubewardenCARootCACert]
	if !ok {
		return nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}
	caPrivateKeyBytes, ok := caSecret.Data[constants.KubewardenCARootPrivateKeyCertName]
	if !ok {
		return nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CA private key could not be extracted from secret %s", caSecret.Kind)
	}
	return &admissionregistration.CA{CaCert: caCert, CaPrivateKey: caPrivateKey}, nil
}

// FetchOrInitializeRootCASecret checks if the root CA secret exists and
// creates it if it does not.  It returns the secret containing the root CA, a
// boolean flag to signal if the secret has been initialize now and an error in
// case of failure.
func (r *Reconciler) FetchOrInitializeRootCASecret(ctx context.Context, generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, bool, error) {
	CASecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.KubewardenCARootSecretName},
		&CASecret)
	if err != nil && apierrors.IsNotFound(err) {
		CASecret, err := r.buildRootCASecret(generateCA, pemEncodeCertificate)
		if err != nil {
			return &corev1.Secret{}, false, err
		}
		if err := r.reconcileCASecret(ctx, CASecret); err != nil {
			return &corev1.Secret{}, false, err
		}
		return CASecret, true, nil
	}

	CASecret.ResourceVersion = ""
	if err != nil {
		return &corev1.Secret{}, false,
			fmt.Errorf("cannot fetch or initialize Policy Server CA secret: %w", err)
	}
	return &CASecret, false, nil
}

// FetchKubewardenCARootSecret function used to get the secret storing the root
// CA secret used by Kubewarden controllers.
func (r *Reconciler) FetchKubewardenCARootSecret(ctx context.Context) (*corev1.Secret, error) {
	policyServerSecret := corev1.Secret{}
	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Namespace: r.DeploymentsNamespace,
			Name:      constants.KubewardenCARootSecretName},
		&policyServerSecret)
	if err != nil {
		return &corev1.Secret{},
			fmt.Errorf("cannot fetch or initialize root CA secret: %w", err)
	}

	return &policyServerSecret, nil
}

// buildRootCASecret build the secret object to be used as root CA generateCA
// is a function used to generate the secret CA and pemEncodeCertificateFunc is
// the function used to encode the root ca cert
func (r *Reconciler) buildRootCASecret(generateCA generateCAFunc, pemEncodeCertificate pemEncodeCertificateFunc) (*corev1.Secret, error) {
	caRoot, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("cannot generate policy-server secret CA: %w", err)
	}
	caPEMEncoded, err := pemEncodeCertificate(caRoot.CaCert)
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy-server secret CA: %w", err)
	}
	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(caRoot.CaPrivateKey)
	secretContents := map[string][]byte{
		constants.KubewardenCARootCACert:             caRoot.CaCert,
		constants.KubewardenCARootPemName:            caPEMEncoded,
		constants.KubewardenCARootPrivateKeyCertName: caPrivateKeyBytes,
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.KubewardenCARootSecretName,
			Namespace: r.DeploymentsNamespace,
		},
		Data: secretContents,
		Type: corev1.SecretTypeOpaque,
	}, nil
}

// ReconcilePolicyServerSecret reconcile the policy server secret when necessary.
//
// policyServer is the Policy Server is a reference to the policy server ca secret which to be reconciled
//
// caRootSecret is the root CA secret to be used when the policy server secret is initilizaed
//
// forceRecreateSecret is a flag to for the policy server's secret initialization even if the secret already exists.
// This is used when the root ca is recreated and the policy server secret should be updated.
func (r *Reconciler) ReconcilePolicyServerSecret(
	ctx context.Context,
	policyServer *policiesv1.PolicyServer,
	caRootSecret *corev1.Secret,
	forceRecreateSecret bool,
) error {

	policyServerCASecret, err := r.fetchPolicyServerCASecret(ctx, policyServer)
	if err != nil && apierrors.IsNotFound(err) || forceRecreateSecret {
		policyServerCASecret, err = r.initializePolicyServerCASecret(policyServer, caRootSecret, admissionregistration.GenerateCert)
		if err != nil {
			setFalseConditionType(
				&policyServer.Status.Conditions,
				string(policiesv1.PolicyServerCASecretReconciled),
				fmt.Sprintf("error reconciling secret: %v", err),
			)
			return err
		}
	}

	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCASecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileCASecret(ctx, policyServerCASecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCASecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCASecretReconciled),
	)
	return nil
}

// UpdateAllPolicyServerSecrets get all secret storing the CA secret used by all
// policy servers and update them using the given caSecret.
func (r *Reconciler) UpdateAllPolicyServerSecrets(ctx context.Context, caSecret *corev1.Secret) error {
	secrets := &corev1.SecretList{}
	err := r.Client.List(ctx, secrets)
	if err != nil {
		return err
	}
	for _, secret := range secrets.Items {
		policyServerName, ok := secret.Labels[constants.PolicyServerLabelKey]
		if !ok {
			r.Log.Info("Cannot get policy server name. Skipping", "secret name", secret.Name, "missing label", constants.PolicyServerLabelKey)
			continue
		}
		policyServer := &policiesv1.PolicyServer{}
		if err := r.Client.Get(ctx, client.ObjectKey{Name: policyServerName}, policyServer); err != nil {
			r.Log.Error(err, "Cannot get PolicyServer object", "policy server", policyServerName)
			continue
		}
		if err := r.ReconcilePolicyServerSecret(ctx, policyServer, caSecret, true); err != nil {
			r.Log.Error(err, "Failed to reconcile policy server secret", "policy server", policyServerName)
			continue
		}
	}
	return nil
}
