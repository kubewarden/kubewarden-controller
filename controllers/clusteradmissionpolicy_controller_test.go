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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
)

var _ = Describe("ClusterAdmissionPolicy controller", func() {
	var policyServerName string

	BeforeEach(func() {
		policyServerName = newName("policy-server")
	})

	When("creating a validating ClusterAdmissionPolicy", func() {
		var policyName string
		var policy *policiesv1.ClusterAdmissionPolicy

		BeforeEach(func() {
			policyName = newName("validating-policy")
			createPolicyServerAndWaitForItsService(policyServerFactory(policyServerName))
			policy = clusterAdmissionPolicyFactory(policyName, policyServerName, false)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the ClusterAdmissionPolicy to active", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
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
				Expect(validatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey]).To(Equal("cluster"))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(BeEmpty())
				Expect(validatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal(fmt.Sprintf("policy-server-%s", policyServerName)))

				caSecret, err := getTestCASecret()
				Expect(err).ToNot(HaveOccurred())
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.PolicyServerCARootPemName]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should be reconcile the ValidationWebhookConfiguration to the original state after some change", func() {
			By("changing the ValidatingWebhookConfiguration")
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
				return getTestValidatingWebhookConfiguration(fmt.Sprintf("clusterwide-%s", policyName))
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalValidatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalValidatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalValidatingWebhookConfiguration.Webhooks)),
				),
			)
		})
	})

	When("creating a mutating ClusterAdmissionPolicy", func() {
		var policyName string
		var policy *policiesv1.ClusterAdmissionPolicy

		BeforeEach(func() {
			policyName = newName("mutating-policy")
			createPolicyServerAndWaitForItsService(policyServerFactory(policyServerName))
			policy = clusterAdmissionPolicyFactory(policyName, policyServerName, true)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the AdmissionPolicy to active", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
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
				Expect(mutatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey]).To(Equal("cluster"))
				Expect(mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(BeEmpty())
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
				return getTestMutatingWebhookConfiguration(fmt.Sprintf("clusterwide-%s", policyName))
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalMutatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalMutatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalMutatingWebhookConfiguration.Webhooks)),
				),
			)
		})
	})

	It("should set policy status to unscheduled when creating an ClusterAdmissionPolicy without a PolicyServer assigned", func() {
		policyName := newName("unscheduled-policy")
		Expect(
			k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, "", false)),
		).To(haveSucceededOrAlreadyExisted())

		Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
			return getTestClusterAdmissionPolicy(policyName)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusUnscheduled)),
		)
	})

	When("creating a ClusterAdmissionPolicy with a PolicyServer assigned but not running yet", func() {
		var policyName string

		BeforeEach(func() {
			policyName = newName("scheduled-policy")
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(haveSucceededOrAlreadyExisted())
		})

		It("should set the policy status to scheduled", func() {
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(haveSucceededOrAlreadyExisted())

			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
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
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})
	})
})
