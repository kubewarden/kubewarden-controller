package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/certs"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const tickerDuration = 12 * time.Hour

type CertReconciler struct {
	client.Client
	Log                         logr.Logger
	DeploymentsNamespace        string
	WebhookServiceName          string
	CARootSecretName            string
	WebhookServerCertSecretName string
}

// Start begins the periodic reconciler.
// Implements the Runnable inteface, see https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/manager#Runnable.
func (r *CertReconciler) Start(ctx context.Context) error {
	r.Log.Info("Starting CertController ticker")

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("Stopping CertController")
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				r.Log.Error(err, "Failed to")
			}
		}
	}
}

// NeedLeaderElection returns true to ensure that only one instance of the controller is running at a time.
// Implements the LeaderElectionRunnable interface, see https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/manager#LeaderElectionRunnable.
func (r *CertReconciler) NeedLeaderElection() bool {
	return true
}

func (r *CertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	return nil
}

// reconcile reconciles the CA root and server certificates by rotating them if they are about to expire.
func (r *CertReconciler) reconcile(ctx context.Context) error {
	caCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.CARootSecretName, Namespace: r.DeploymentsNamespace}, caCertSecret); err != nil {
		return fmt.Errorf("failed to get CA cert secret: %w", err)
	}

	if err := r.reconcileCARoot(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile CA root: %w", err)
	}
	if err := r.reconcileOldCARoot(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile old CA root: %w", err)
	}
	if err := r.reconcileServerCerts(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile server certs: %w", err)
	}

	return nil
}

// reconcileCARoot reconciles the CA root certificate by rotating it if it is about to expire.
// It saves the old CA root certificate in the secret so that we can remove it after it is no longer valid.
// Also, it updates the webhook configurations by injecting a bundle containing the new and old CA root certificates.
func (r *CertReconciler) reconcileCARoot(ctx context.Context, caRootSecret *corev1.Secret) error {
	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA root from secret: %w", err)
	}

	if err = certs.VerifyCA(caCert, caPrivateKey, time.Now().Add(constants.CertLookahead)); err != nil {
		r.Log.Info("CA root certificate verification failed, rotating CA root the certificate", "verification error", err)

		oldCACert := caCert
		caCert, caPrivateKey, err = certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
		if err != nil {
			return fmt.Errorf("failed to generate CA cert: %w", err)
		}

		caRootSecret.Data[constants.CARootCert] = caCert
		caRootSecret.Data[constants.CARootPrivateKey] = caPrivateKey
		caRootSecret.Data[constants.OldCARootCert] = oldCACert
		if err = r.Update(ctx, caRootSecret); err != nil {
			return fmt.Errorf("failed to update CA root secret: %w", err)
		}

		err = r.reconcileWebhookConfigurations(ctx, append(caCert, oldCACert...))
		if err != nil {
			return fmt.Errorf("failed to reconcile webhook configurations: %w", err)
		}

		r.Log.Info("CA root certificate rotated successfully")
	}

	return nil
}

// reconcileOldCARoot reconciles the old CA root certificate by removing it if it is no longer valid.
// It also updates the webhook configurations by removing the old CA root certificate from the CA bundle.
func (r *CertReconciler) reconcileOldCARoot(ctx context.Context, caRootSecret *corev1.Secret) error {
	oldCACert, ok := caRootSecret.Data[constants.OldCARootCert]
	if !ok {
		return nil
	}

	if err := certs.VerifyCA(oldCACert, nil, time.Now()); err != nil {
		r.Log.Info("Old CA root certificate is not valid anymore, removing the old CA root certificate", "verification error", err)

		var caCert []byte
		caCert, _, err = certs.ExtractCARootFromSecret(caRootSecret)
		if err != nil {
			return fmt.Errorf("failed to extract CA root from secret: %w", err)
		}

		delete(caRootSecret.Data, constants.OldCARootCert)
		if err = r.Update(ctx, caRootSecret); err != nil {
			return fmt.Errorf("failed to update CA root secret: %w", err)
		}

		err = r.reconcileWebhookConfigurations(ctx, caCert)
		if err != nil {
			return fmt.Errorf("failed to reconcile webhook configurations: %w", err)
		}

		r.Log.Info("Old CA root certificate removed successfully")
	}

	return nil
}

// reconcileWebhookConfigurations reconciles the webhook configurations by injecting the CA bundle.
// Note that we are using RetryOnConflict to handle potential conflicts when updating the webhook configurations.
// This is necessary because the webhook configurations could be update by the AdmissionPolicy and ClusterAdmissionPolicy controllers.
func (r *CertReconciler) reconcileWebhookConfigurations(ctx context.Context, caBundle []byte) error {
	validatingWebhookConfigurationList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, validatingWebhookConfigurationList, client.MatchingLabels{
		"app.kubernetes.io/part-of": "kubewarden",
	}); err != nil {
		return fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}

	for _, validatingWebhookConfiguration := range validatingWebhookConfigurationList.Items {
		original := validatingWebhookConfiguration.DeepCopy()
		for i := range validatingWebhookConfiguration.Webhooks {
			validatingWebhookConfiguration.Webhooks[i].ClientConfig.CABundle = caBundle
		}

		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			return r.Patch(ctx, &validatingWebhookConfiguration, client.MergeFrom(original))
		})
		if err != nil {
			return fmt.Errorf("failed to patch validating webhook configuration: %w", err)
		}
	}

	mutatingWebhookConfigurationList := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := r.List(ctx, mutatingWebhookConfigurationList, client.MatchingLabels{
		"app.kubernetes.io/part-of": "kubewarden",
	}); err != nil {
		return fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	for _, mutatingWebhookConfiguration := range mutatingWebhookConfigurationList.Items {
		original := mutatingWebhookConfiguration.DeepCopy()
		for i := range mutatingWebhookConfiguration.Webhooks {
			mutatingWebhookConfiguration.Webhooks[i].ClientConfig.CABundle = caBundle
		}

		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			return r.Patch(ctx, &mutatingWebhookConfiguration, client.MergeFrom(original))
		})
		if err != nil {
			return fmt.Errorf("failed to patch mutating webhook configuration: %w", err)
		}
	}

	return nil
}

// reconcileServerCerts reconciles the webhook server and policy server certificates by rotating them if they are about to expire.
func (r *CertReconciler) reconcileServerCerts(ctx context.Context, caRootSecret *corev1.Secret) error {
	webhookServerCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.WebhookServerCertSecretName, Namespace: r.DeploymentsNamespace}, webhookServerCertSecret); err != nil {
		return fmt.Errorf("failed to get webhook server cert secret: %w", err)
	}
	dnsName := certs.DNSName(r.WebhookServiceName, r.DeploymentsNamespace)
	if err := r.reconcileServerCert(ctx, webhookServerCertSecret, caRootSecret, dnsName); err != nil {
		return fmt.Errorf("failed to rotate server cert: %w", err)
	}

	serverCertSecretList := &corev1.SecretList{}
	err := r.List(ctx,
		serverCertSecretList,
		client.InNamespace(r.DeploymentsNamespace),
		client.MatchingLabels{
			"app.kubernetes.io/part-of":   "kubewarden",
			"app.kubernetes.io/component": "policy-server",
		},
	)
	if err != nil {
		return fmt.Errorf("failed to list policy server cert secrets: %w", err)
	}

	for _, serverCertSecret := range serverCertSecretList.Items {
		dnsName = certs.DNSName(serverCertSecret.GetName(), r.DeploymentsNamespace)
		if err = r.reconcileServerCert(ctx, &serverCertSecret, caRootSecret, dnsName); err != nil {
			return fmt.Errorf("failed to rotate server cert: %w", err)
		}
	}

	return nil
}

// reconcileServerCert reconciles the server certificate by rotating it if it is about to expire.
func (r *CertReconciler) reconcileServerCert(ctx context.Context, serverCertSecret *corev1.Secret, caRootSecret *corev1.Secret, dnsName string) error {
	cert, privateKey, err := certs.ExtractServerCertFromSecret(serverCertSecret)
	if err != nil {
		return fmt.Errorf("failed to extract server cert from secret: %w", err)
	}

	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA root from secret: %w", err)
	}

	pool, err := certs.NewCertPool(caCert)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	if err = certs.VerifyCert(cert, privateKey, pool, dnsName, time.Now().Add(constants.CertLookahead)); err != nil {
		r.Log.Info("Certificate verification failed, rotating the certificate", "dnsName", dnsName, "verification error", err)

		var newCert, newPrivateKey []byte
		newCert, newPrivateKey, err = certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), dnsName)
		if err != nil {
			return fmt.Errorf("failed to generate cert: %w", err)
		}

		serverCertSecret.Data[constants.ServerCert] = newCert
		serverCertSecret.Data[constants.ServerPrivateKey] = newPrivateKey

		if err = r.Update(ctx, serverCertSecret); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		r.Log.Info("Certificate rotated successfully", "dnsName", dnsName)
	}

	return nil
}
