/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//nolint:dupl
package controllers

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("AdmissionPolicy controller", func() {
	var policyNamespace string
	var policyServerName string

	BeforeEach(func() {
		policyNamespace = "admission-policy-controller-test"
		policyServerName = newName("policy-server")
		Expect(
			k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: policyNamespace,
				},
			}),
		).To(haveSucceededOrAlreadyExisted())
	})

	When("creating a validating AdmissionPolicy", func() {
		var policyName string
		var policy *policiesv1.AdmissionPolicy

		BeforeEach(func() {
			policyName = newName("validating-policy")
			createPolicyServerAndWaitForItsService(policyServerFactory(policyServerName))
			policy = admissionPolicyFactory(policyName, policyNamespace, policyServerName, false)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the AdminissionPolicy to active sometime after its creation", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the ValidatingWebhookConfiguration", func() {
			Eventually(func() error {
				validatingWebhookConfiguration, err := getTestValidatingWebhookConfiguration(policy.GetUniqueName())
				if err != nil {
					return err
				}

				Expect(validatingWebhookConfiguration.Labels["kubewarden"]).To(Equal("true"))
				Expect(validatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey]).To(Equal("namespace"))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(Equal(policyNamespace))
				Expect(validatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal(fmt.Sprintf("policy-server-%s", policyServerName)))

				caSecret, err := getTestCASecret()
				Expect(err).ToNot(HaveOccurred())
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.PolicyServerCARootPemName]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should be reconcile the ValidationWebhookConfiguration to the original state after some change", func() {
			var originalValidatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration
			var validatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration
			Eventually(func() error {
				var err error
				validatingWebhookConfiguration, err = getTestValidatingWebhookConfiguration(policy.GetUniqueName())
				if err != nil {
					return err
				}
				originalValidatingWebhookConfiguration = validatingWebhookConfiguration.DeepCopy()
				return nil
			}, timeout, pollInterval).Should(Succeed())

			By("changing the ValidatingWebhookConfiguration")
			delete(validatingWebhookConfiguration.Labels, "kubewarden")
			validatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey] = newName("scope")
			delete(validatingWebhookConfiguration.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = newName("namespace")
			validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name = newName("service")
			validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			Expect(
				k8sClient.Update(ctx, validatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the ValidatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
				return getTestValidatingWebhookConfiguration(policy.GetUniqueName())
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalValidatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalValidatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalValidatingWebhookConfiguration.Webhooks)),
				),
			)

			// simulate unitialized labels and annotation maps (behaviour of Kubewarden <= 1.9.0), or user change
			By("setting the ValidatingWebhookConfiguration labels and annotation to nil")
			validatingWebhookConfiguration, err := getTestValidatingWebhookConfiguration(policy.GetUniqueName())
			Expect(err).ToNot(HaveOccurred())
			originalValidatingWebhookConfiguration = validatingWebhookConfiguration.DeepCopy()
			validatingWebhookConfiguration.Labels = nil
			validatingWebhookConfiguration.Annotations = nil
			Expect(
				k8sClient.Update(ctx, validatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the ValidatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
				return getTestValidatingWebhookConfiguration(policy.GetUniqueName())
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalValidatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalValidatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalValidatingWebhookConfiguration.Webhooks)),
				),
			)
		})
	})

	When("creating a mutating AdmissionPolicy", func() {
		var policyName string
		var policy *policiesv1.AdmissionPolicy

		BeforeEach(func() {
			policyName = newName("mutating-policy")
			createPolicyServerAndWaitForItsService(policyServerFactory(policyServerName))
			policy = admissionPolicyFactory(policyName, policyNamespace, policyServerName, true)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the AdmissionPolicy to active", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the MutatingWebhookConfiguration", func() {
			Eventually(func() error {
				mutatingWebhookConfiguration, err := getTestMutatingWebhookConfiguration(policy.GetUniqueName())
				if err != nil {
					return err
				}

				Expect(mutatingWebhookConfiguration.Labels["kubewarden"]).To(Equal("true"))
				Expect(mutatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey]).To(Equal("namespace"))
				Expect(mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(Equal(policyNamespace))
				Expect(mutatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(mutatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal(fmt.Sprintf("policy-server-%s", policyServerName)))

				caSecret, err := getTestCASecret()
				Expect(err).ToNot(HaveOccurred())
				Expect(mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.PolicyServerCARootPemName]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should be reconcile the MutatingWebhookConfiguration to the original state after some change", func() {
			var originalMutatingWebhookConfiguration *admissionregistrationv1.MutatingWebhookConfiguration
			var mutatingWebhookConfiguration *admissionregistrationv1.MutatingWebhookConfiguration
			Eventually(func() error {
				var err error
				mutatingWebhookConfiguration, err = getTestMutatingWebhookConfiguration(policy.GetUniqueName())
				if err != nil {
					return err
				}
				originalMutatingWebhookConfiguration = mutatingWebhookConfiguration.DeepCopy()
				return nil
			}, timeout, pollInterval).Should(Succeed())

			By("changing the MutatingWebhookConfiguration")
			delete(mutatingWebhookConfiguration.Labels, "kubewarden")
			mutatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey] = newName("scope")
			delete(mutatingWebhookConfiguration.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = newName("namespace")
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name = newName("service")
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			Expect(
				k8sClient.Update(ctx, mutatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the MutatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.MutatingWebhookConfiguration, error) {
				return getTestMutatingWebhookConfiguration(fmt.Sprintf("namespaced-%s-%s", policyNamespace, policyName))
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalMutatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalMutatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalMutatingWebhookConfiguration.Webhooks)),
				),
			)

			// simulate unitialized labels and annotation maps (behaviour of Kubewarden <= 1.9.0), or user change
			By("by setting the MutatingWebhookConfiguration labels and annotation to nil")
			mutatingWebhookConfiguration, err := getTestMutatingWebhookConfiguration(fmt.Sprintf("namespaced-%s-%s", policyNamespace, policyName))
			Expect(err).ToNot(HaveOccurred())
			originalMutatingWebhookConfiguration = mutatingWebhookConfiguration.DeepCopy()
			mutatingWebhookConfiguration.Labels = nil
			mutatingWebhookConfiguration.Annotations = nil
			Expect(
				k8sClient.Update(ctx, mutatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the MutatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.MutatingWebhookConfiguration, error) {
				return getTestMutatingWebhookConfiguration(fmt.Sprintf("namespaced-%s-%s", policyNamespace, policyName))
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalMutatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalMutatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalMutatingWebhookConfiguration.Webhooks)),
				),
			)
		})

	})

	It("should set policy status to unscheduled when creating an AdmissionPolicy without a PolicyServer assigned", func() {
		policyName := newName("unscheduled-policy")
		Expect(
			k8sClient.Create(ctx, admissionPolicyFactory(policyName, policyNamespace, "", false)),
		).To(haveSucceededOrAlreadyExisted())

		Eventually(func() (*policiesv1.AdmissionPolicy, error) {
			return getTestAdmissionPolicy(policyNamespace, policyName)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusUnscheduled)),
		)

	})

	When("creating an AdmissionPolicy with a PolicyServer assigned but not running yet", func() {
		var policyName string

		BeforeEach(func() {
			policyName = newName("scheduled-policy")
			Expect(
				k8sClient.Create(ctx, admissionPolicyFactory(policyName, policyNamespace, policyServerName, false)),
			).To(haveSucceededOrAlreadyExisted())
		})

		It("should set the policy status to scheduled", func() {
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusScheduled)),
			)
		})

		It("should set the policy status to active when the PolicyServer is created", func() {
			By("creating the PolicyServer")
			Expect(
				k8sClient.Create(ctx, policyServerFactory(policyServerName)),
			).To(haveSucceededOrAlreadyExisted())

			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.AdmissionPolicy, error) {
				return getTestAdmissionPolicy(policyNamespace, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})
	})
})
