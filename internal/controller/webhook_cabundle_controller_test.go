package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// The specs change the shared CA root secret, so they must not run in parallel with other specs.
var _ = Describe("Webhook CA bundle reconciler", Serial, func() {
	ctx := context.Background()
	injectCAFromCARootSecret := deploymentsNamespace + "/" + constants.CARootSecretName

	var otherCABundle []byte

	BeforeEach(func() {
		otherCACert, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
		Expect(err).ToNot(HaveOccurred())
		otherCABundle = otherCACert
	})

	// The webhooks have no rules, so that they do not intercept the requests of the other specs.
	newValidatingWebhookConfiguration := func(annotations map[string]string, caBundle []byte) *admissionregistrationv1.ValidatingWebhookConfiguration {
		return &admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:        newName("webhook-cabundle-validating"),
				Annotations: annotations,
			},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name: "first.webhook-cabundle.kubewarden.test",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: "webhook-cabundle"},
						CABundle: caBundle,
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				},
				{
					Name: "second.webhook-cabundle.kubewarden.test",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: "webhook-cabundle"},
						CABundle: caBundle,
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				},
			},
		}
	}
	newMutatingWebhookConfiguration := func(annotations map[string]string, caBundle []byte) *admissionregistrationv1.MutatingWebhookConfiguration {
		return &admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:        newName("webhook-cabundle-mutating"),
				Annotations: annotations,
			},
			Webhooks: []admissionregistrationv1.MutatingWebhook{
				{
					Name: "first.webhook-cabundle.kubewarden.test",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: "webhook-cabundle"},
						CABundle: caBundle,
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				},
			},
		}
	}

	create := func(object client.Object) {
		Expect(k8sClient.Create(ctx, object)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed())
		})
	}

	expectedCABundle := func() []byte {
		caRootSecret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.CARootSecretName}, caRootSecret)).To(Succeed())
		return certs.CABundleFromSecret(caRootSecret)
	}

	validatingCABundles := func(name string) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, webhookConfiguration); err != nil {
				return nil, err
			}
			caBundles := [][]byte{}
			for _, webhook := range webhookConfiguration.Webhooks {
				caBundles = append(caBundles, webhook.ClientConfig.CABundle)
			}
			return caBundles, nil
		}
	}
	mutatingCABundles := func(name string) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			webhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{}
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, webhookConfiguration); err != nil {
				return nil, err
			}
			caBundles := [][]byte{}
			for _, webhook := range webhookConfiguration.Webhooks {
				caBundles = append(caBundles, webhook.ClientConfig.CABundle)
			}
			return caBundles, nil
		}
	}

	updateCARootSecret := func(mutate func(secret *corev1.Secret)) {
		Eventually(func() error {
			caRootSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.CARootSecretName}, caRootSecret); err != nil {
				return err
			}
			mutate(caRootSecret)
			return k8sClient.Update(ctx, caRootSecret)
		}, timeout, pollInterval).Should(Succeed())
	}

	It("should repair a webhook configuration that is created with the CA bundle of another CA", func() {
		annotations := map[string]string{constants.InjectCAFromAnnotationKey: injectCAFromCARootSecret}
		validating := newValidatingWebhookConfiguration(annotations, otherCABundle)
		create(validating)
		mutating := newMutatingWebhookConfiguration(annotations, otherCABundle)
		create(mutating)

		Eventually(validatingCABundles(validating.Name), timeout, pollInterval).Should(HaveEach(Equal(expectedCABundle())))
		Eventually(mutatingCABundles(mutating.Name), timeout, pollInterval).Should(HaveEach(Equal(expectedCABundle())))
	})

	It("should repair a webhook configuration whose CA bundle changes to the bundle of another CA", func() {
		annotations := map[string]string{constants.InjectCAFromAnnotationKey: injectCAFromCARootSecret}
		validating := newValidatingWebhookConfiguration(annotations, expectedCABundle())
		create(validating)

		By("writing the CA bundle of another CA")
		Eventually(func() error {
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(validating), webhookConfiguration); err != nil {
				return err
			}
			webhookConfiguration.Webhooks[0].ClientConfig.CABundle = otherCABundle
			return k8sClient.Update(ctx, webhookConfiguration)
		}, timeout, pollInterval).Should(Succeed())

		Eventually(validatingCABundles(validating.Name), timeout, pollInterval).Should(HaveEach(Equal(expectedCABundle())))
	})

	It("should repair a webhook configuration when the annotation is added", func() {
		validating := newValidatingWebhookConfiguration(nil, otherCABundle)
		create(validating)

		By("adding the annotation")
		Eventually(func() error {
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(validating), webhookConfiguration); err != nil {
				return err
			}
			webhookConfiguration.Annotations = map[string]string{constants.InjectCAFromAnnotationKey: injectCAFromCARootSecret}
			return k8sClient.Update(ctx, webhookConfiguration)
		}, timeout, pollInterval).Should(Succeed())

		Eventually(validatingCABundles(validating.Name), timeout, pollInterval).Should(HaveEach(Equal(expectedCABundle())))
	})

	It("should write the new CA bundle when the CA root secret changes", func() {
		annotations := map[string]string{constants.InjectCAFromAnnotationKey: injectCAFromCARootSecret}
		validating := newValidatingWebhookConfiguration(annotations, expectedCABundle())
		create(validating)
		mutating := newMutatingWebhookConfiguration(annotations, expectedCABundle())
		create(mutating)

		oldCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			updateCARootSecret(func(secret *corev1.Secret) {
				delete(secret.Data, constants.OldCARootCert)
			})
		})

		By("adding the old CA certificate to the CA root secret")
		updateCARootSecret(func(secret *corev1.Secret) {
			secret.Data[constants.OldCARootCert] = oldCACert
		})
		bundleWithOldCA := expectedCABundle()
		Expect(bundleWithOldCA).To(HaveSuffix(string(oldCACert)))
		Eventually(validatingCABundles(validating.Name), timeout, pollInterval).Should(HaveEach(Equal(bundleWithOldCA)))
		Eventually(mutatingCABundles(mutating.Name), timeout, pollInterval).Should(HaveEach(Equal(bundleWithOldCA)))

		By("removing the old CA certificate from the CA root secret")
		updateCARootSecret(func(secret *corev1.Secret) {
			delete(secret.Data, constants.OldCARootCert)
		})
		bundleWithoutOldCA := expectedCABundle()
		Expect(bundleWithoutOldCA).ToNot(Equal(bundleWithOldCA))
		Eventually(validatingCABundles(validating.Name), timeout, pollInterval).Should(HaveEach(Equal(bundleWithoutOldCA)))
		Eventually(mutatingCABundles(mutating.Name), timeout, pollInterval).Should(HaveEach(Equal(bundleWithoutOldCA)))
	})

	It("should not patch a webhook configuration with the correct CA bundle", func() {
		annotations := map[string]string{constants.InjectCAFromAnnotationKey: injectCAFromCARootSecret}
		validating := newValidatingWebhookConfiguration(annotations, expectedCABundle())
		create(validating)

		Consistently(func() (string, error) {
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(validating), webhookConfiguration); err != nil {
				return "", err
			}
			return webhookConfiguration.ResourceVersion, nil
		}, consistencyTimeout, pollInterval).Should(Equal(validating.ResourceVersion))
	})

	It("should not touch a webhook configuration without the annotation", func() {
		validating := newValidatingWebhookConfiguration(nil, otherCABundle)
		create(validating)

		Consistently(validatingCABundles(validating.Name), consistencyTimeout, pollInterval).Should(HaveEach(Equal(otherCABundle)))
	})

	It("should not touch a webhook configuration whose annotation names another secret", func() {
		validating := newValidatingWebhookConfiguration(map[string]string{constants.InjectCAFromAnnotationKey: "other-namespace/other-secret"}, otherCABundle)
		create(validating)

		Consistently(validatingCABundles(validating.Name), consistencyTimeout, pollInterval).Should(HaveEach(Equal(otherCABundle)))
	})
})
