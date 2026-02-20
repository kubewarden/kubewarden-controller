package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

var _ = Describe("PolicyServer certificate secret reconciliation", func() {
	ctx := context.Background()
	var policyServerName string

	BeforeEach(func() {
		policyServerName = newName("policy-server-testcert")
	})

	When("a PolicyServer is created", func() {
		It("should create the cert secret with certificate data, format annotation, and correct type and labels", func() {
			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				secret, err := getTestPolicyServerSecret(ctx, policyServerName)
				if err != nil {
					return err
				}

				By("verifying the secret type")
				Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))

				By("verifying the certificate data was generated")
				Expect(secret.Data).To(HaveKey(constants.ServerCert))
				Expect(secret.Data[constants.ServerCert]).ToNot(BeEmpty())
				Expect(secret.Data).To(HaveKey(constants.ServerPrivateKey))
				Expect(secret.Data[constants.ServerPrivateKey]).ToNot(BeEmpty())

				By("verifying the format version annotation was added")
				Expect(secret.Annotations).To(HaveKeyWithValue(
					constants.ServerCertSecretFormatAnnotation,
					constants.ServerCertSecretFormatVersion,
				))

				By("verifying the labels were set")
				Expect(secret.Labels).To(HaveKeyWithValue(constants.PartOfLabelKey, constants.PartOfLabelValue))
				Expect(secret.Labels).To(HaveKeyWithValue(constants.ComponentLabelKey, constants.ComponentPolicyServerLabelValue))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})
	})

	When("a cert secret without the format annotation already exists", func() {
		It("should regenerate the certificate and add the format annotation", func() {
			By("pre-creating the cert secret without the format annotation")
			preExistingSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyServerNameWithPrefix(policyServerName),
					Namespace: deploymentsNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       []byte("old-cert-data"),
					constants.ServerPrivateKey: []byte("old-key-data"),
				},
			}
			Expect(k8sClient.Create(ctx, preExistingSecret)).To(Succeed())

			policyServer := policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build()
			createPolicyServerAndWaitForItsService(ctx, policyServer)

			Eventually(func() error {
				secret, err := getTestPolicyServerSecret(ctx, policyServerName)
				if err != nil {
					return err
				}

				By("verifying the format version annotation was added")
				Expect(secret.Annotations).To(HaveKeyWithValue(
					constants.ServerCertSecretFormatAnnotation,
					constants.ServerCertSecretFormatVersion,
				))

				By("verifying the certificate was regenerated")
				Expect(secret.Data[constants.ServerCert]).ToNot(Equal([]byte("old-cert-data")))

				By("verifying the secret type and labels")
				Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
				Expect(secret.Labels).To(HaveKeyWithValue(constants.PartOfLabelKey, constants.PartOfLabelValue))
				Expect(secret.Labels).To(HaveKeyWithValue(constants.ComponentLabelKey, constants.ComponentPolicyServerLabelValue))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})
	})
})
