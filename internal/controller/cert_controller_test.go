package controller

import (
	"context"
	"time"

	"github.com/kubewarden/kubewarden-controller/internal/certs"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

var _ = Describe("Cert controller", func() {
	ctx := context.Background()

	Context("Server certificates rotation", Ordered, func() {
		const (
			webhookServerServiceName    = "server-cert-rotation-test-webhook-service"
			caRootSecretName            = "server-cert-rotation-test-ca-root"
			webhookServerCertSecretName = "server-cert-rotation-test-webhook-server-cert"
			policyServerName            = "server-cert-rotation-test-policy-server"
		)

		BeforeAll(func() {
			certController := CertReconciler{
				Client:                      k8sClient,
				DeploymentsNamespace:        deploymentsNamespace,
				WebhookServiceName:          webhookServerServiceName,
				CARootSecretName:            caRootSecretName,
				WebhookServerCertSecretName: webhookServerCertSecretName,
			}

			By("generating the CA cert")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			Expect(err).ToNot(HaveOccurred())
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      caRootSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating webhook server cert that is about to expire")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("generating a policy server cert that is about to expire")
			policyServerDNSName := certs.DNSName(policyServerName, deploymentsNamespace)
			policyServerCert, policyServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), policyServerDNSName)
			Expect(err).ToNot(HaveOccurred())
			policyServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      policyServerName,
					Labels: map[string]string{
						"app.kubernetes.io/part-of":   "kubewarden",
						"app.kubernetes.io/component": "policy-server",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       policyServerCert,
					constants.ServerPrivateKey: policyServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, policyServerCertSecret)).To(Succeed())

			By("reconciling")
			Expect(certController.reconcile(ctx)).To(Succeed())
		})

		It("should rotate the webhook server certificate", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			By("fetching the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: webhookServerCertSecretName, Namespace: deploymentsNamespace}, webhookServerCertSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the webhook server cert secret has been rotated")
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			err = certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("should rotate the policy server certificates", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			By("fetching the policy server cert secrets")
			policyServerSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "server-cert-rotation-test-policy-server", Namespace: deploymentsNamespace}, policyServerSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the policy server cert secret has been rotated")
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(policyServerSecret.GetName(), deploymentsNamespace)
			err = certs.VerifyCert(policyServerSecret.Data[constants.ServerCert], policyServerSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("CA root rotation", Ordered, func() {
		const (
			webhookServerServiceName           = "ca-root-rotation-test-webhook-service"
			caRootSecretName                   = "ca-root-rotation-test-ca-root"
			webhookServerCertSecretName        = "ca-root-rotation-test-webhook-server-cert"
			policyServerName                   = "ca-root-rotation-test-policy-server"
			validatingWebhookConfigurationName = "ca-root-rotation-test-validating-webhook-configuration"
			mutatingWebhookConfigurationName   = "ca-root-rotation-test-mutating-webhook-configuration"
		)

		var webhookServerCert, webhookServerPrivateKey []byte

		BeforeAll(func() {
			certController := CertReconciler{
				Client:                      k8sClient,
				DeploymentsNamespace:        deploymentsNamespace,
				WebhookServiceName:          webhookServerServiceName,
				CARootSecretName:            caRootSecretName,
				WebhookServerCertSecretName: webhookServerCertSecretName,
			}

			By("generating a CA cert that is about to expire")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
			Expect(err).ToNot(HaveOccurred())
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      caRootSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating a webhook server cert")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err = certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("creating a validating webhook configuration")
			validatingWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: validatingWebhookConfigurationName,
					Labels: map[string]string{
						"app.kubernetes.io/part-of": "kubewarden",
					},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "kubewarden.webhook.test",

						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service: &admissionregistrationv1.ServiceReference{
								Namespace: deploymentsNamespace,
								Name:      webhookServerServiceName,
							},
							CABundle: caCert,
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, validatingWebhookConfiguration)).To(Succeed())

			By("creating a mutating webhook configuration")
			mutatingWebhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: mutatingWebhookConfigurationName,
					Labels: map[string]string{
						"app.kubernetes.io/part-of": "kubewarden",
					},
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{
					{
						Name: "kubewarden.webhook.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service: &admissionregistrationv1.ServiceReference{
								Namespace: deploymentsNamespace,
								Name:      webhookServerServiceName,
							},
							CABundle: caCert,
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, mutatingWebhookConfiguration)).To(Succeed())

			By("creating a policy server cert secret")
			policyServerDNSName := certs.DNSName(policyServerName, deploymentsNamespace)
			policyServerCert, policyServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), policyServerDNSName)
			Expect(err).ToNot(HaveOccurred())
			policyServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      policyServerName,
					Labels: map[string]string{
						"app.kubernetes.io/part-of":   "kubewarden",
						"app.kubernetes.io/component": "policy-server",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       policyServerCert,
					constants.ServerPrivateKey: policyServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, policyServerCertSecret)).To(Succeed())

			By("reconciling")
			Expect(certController.reconcile(ctx)).To(Succeed())
		})

		It("should rotate the CA cert", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the CA cert has been rotated")
			caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			err = certs.VerifyCA(caCert, caPrivateKey, time.Now())
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the old CA cert has beeen added to the secret")
			_, ok := caRootSecret.Data[constants.OldCARootCert]
			Expect(ok).To(BeTrue())
		})

		It("should inject the old + new CA bundle in the webhook configurations and rotate the webhook server cert", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			expectedCABundle := append(caRootSecret.Data[constants.CARootCert], caRootSecret.Data[constants.OldCARootCert]...)

			By("fetching the validating webhook configuration")
			validatingWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: validatingWebhookConfigurationName}, validatingWebhookConfiguration)
			Expect(err).ToNot(HaveOccurred())
			By("checking whether the validating webhook CA bundle contains the old and new CA certs")
			caBundle := validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle
			Expect(expectedCABundle).To(Equal(caBundle))

			By("fetching the mutating webhook configuration")
			mutatingWebhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: mutatingWebhookConfigurationName}, mutatingWebhookConfiguration)
			Expect(err).ToNot(HaveOccurred())
			By("checking whether the mutating webhook CA bundle contains the old and new CA certs")
			caBundle = mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle
			Expect(expectedCABundle).To(Equal(caBundle))

			By("checking whether the old webhook server cert is still valid against the combined CA bundle")
			pool, err := certs.NewCertPool(caBundle)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			err = certs.VerifyCert(webhookServerCert, webhookServerPrivateKey, pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())

			By("fetching the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: webhookServerCertSecretName, Namespace: deploymentsNamespace}, webhookServerCertSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the webhook server cert secret has been rotated")
			err = certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("should rotate the policy server certificates", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			By("fetching the policy server cert secrets")
			policyServerSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName, Namespace: deploymentsNamespace}, policyServerSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether policy server cert secret has been rotated")
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(policyServerSecret.GetName(), deploymentsNamespace)
			err = certs.VerifyCert(policyServerSecret.Data[constants.ServerCert], policyServerSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("Old CA root cleanup", Ordered, func() {
		const (
			webhookServerServiceName           = "old-ca-root-cleanup-test-webhook-service"
			caRootSecretName                   = "old-ca-root-cleanup-test-ca-root"
			webhookServerCertSecretName        = "old-ca-root-cleanup-test-webhook-server-cert"
			policyServerName                   = "old-ca-root-cleanup-test-policy-server"
			validatingWebhookConfigurationName = "old-ca-root-cleanup-test-validating-webhook-configuration"
		)

		BeforeAll(func() {
			certController := CertReconciler{
				Client:                      k8sClient,
				DeploymentsNamespace:        deploymentsNamespace,
				WebhookServiceName:          webhookServerServiceName,
				CARootSecretName:            caRootSecretName,
				WebhookServerCertSecretName: webhookServerCertSecretName,
			}

			By("generating the CA cert")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			Expect(err).ToNot(HaveOccurred())
			By("generating an expired old CA cert")
			oldCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(-24*time.Hour))
			Expect(err).ToNot(HaveOccurred())
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      "old-ca-root-cleanup-test-ca-root",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
					constants.OldCARootCert:    oldCACert,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating a webhook server cert")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("creating a validating webhook configuration with the old and new CA certs in the CA bundle")
			validatingWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: validatingWebhookConfigurationName,
					Labels: map[string]string{
						"app.kubernetes.io/part-of": "kubewarden",
					},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "kubewarden.webhook.test",

						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service: &admissionregistrationv1.ServiceReference{
								Namespace: deploymentsNamespace,
								Name:      webhookServerServiceName,
							},
							CABundle: append(caCert, oldCACert...),
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, validatingWebhookConfiguration)).To(Succeed())

			By("reconciling")
			Expect(certController.reconcile(ctx)).To(Succeed())
		})

		It("should remove the old CA root from the secret", func() {
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			_, ok := caRootSecret.Data[constants.OldCARootCert]
			Expect(ok).To(BeFalse())
		})

		It("should remove the old CA root from the webhook configurations' CA bundle", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			expectedCABundle := caRootSecret.Data[constants.CARootCert]

			By("fetching the validating webhook configuration")
			validatingWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: validatingWebhookConfigurationName}, validatingWebhookConfiguration)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the validating webhook CA bundle contains only the new CA cert")
			caBundle := validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle
			Expect(expectedCABundle).To(Equal(caBundle))
		})
	})
})
