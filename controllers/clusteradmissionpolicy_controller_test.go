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

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
)

var _ = Describe("ClusterAdmissionPolicy controller", func() {
	When("creating a validating ClusterAdmissionPolicy", func() {
		policyServerName := newName("policy-server")
		policyName := newName("validating-policy")

		It("should set the ClusterAdmissionPolicy to active", func() {
			By("creating the PolicyServer")
			Expect(
				k8sClient.Create(ctx, policyServerFactory(policyServerName)),
			).To(Succeed())

			By("creating the ClusterAdmissionPolicy")
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(Succeed())

			By("changing the policy status to pending")
			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the ValidatingWebhookConfiguration", func() {
			Eventually(func(g Gomega) {
				validatingWebhookConfiguration, err := getTestValidatingWebhookConfiguration(fmt.Sprintf("clusterwide-%s", policyName))

				Expect(err).ToNot(HaveOccurred())
				Expect(validatingWebhookConfiguration.Labels["kubewarden"]).To(Equal("true"))
				Expect(validatingWebhookConfiguration.Labels["kubewardenPolicyScope"]).To(Equal("cluster"))
				Expect(validatingWebhookConfiguration.Annotations["kubewardenPolicyName"]).To(Equal(policyName))
				Expect(validatingWebhookConfiguration.Annotations["kubewardenPolicyNamespace"]).To(BeEmpty())
				Expect(validatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal(fmt.Sprintf("policy-server-%s", policyServerName)))
			}, timeout, pollInterval).Should(Succeed())
		})
	})

	When("creating a mutating ClusterAdmissionPolicy", func() {
		policyServerName := newName("policy-server")
		policyName := newName("mutating-policy")

		It("should set the AdmissionPolicy to active", func() {
			By("creating the PolicyServer")
			Expect(
				k8sClient.Create(ctx, policyServerFactory(policyServerName)),
			).To(Succeed())

			By("creating the AdmissionPolicy")
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, true)),
			).To(Succeed())

			By("changing the policy status to pending")
			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the MutatingWebhookConfiguration", func() {
			Eventually(func(g Gomega) {
				mutatingWebhookConfiguration, err := getTestMutatingWebhookConfiguration(fmt.Sprintf("clusterwide-%s", policyName))

				Expect(err).ToNot(HaveOccurred())
				Expect(mutatingWebhookConfiguration.Labels["kubewarden"]).To(Equal("true"))
				Expect(mutatingWebhookConfiguration.Labels["kubewardenPolicyScope"]).To(Equal("cluster"))
				Expect(mutatingWebhookConfiguration.Annotations["kubewardenPolicyName"]).To(Equal(policyName))
				Expect(mutatingWebhookConfiguration.Annotations["kubewardenPolicyNamespace"]).To(BeEmpty())
				Expect(mutatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(mutatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal(fmt.Sprintf("policy-server-%s", policyServerName)))
			}, timeout, pollInterval).Should(Succeed())
		})
	})

	When("creating a ClusterAdmissionPolicy without a PolicyServer assigned", func() {
		policyName := newName("unscheduled-policy")

		It("should set the policy status to unscheduled", func() {
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, "", false)),
			).To(haveSucceededOrAlreadyExisted())

			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusUnscheduled)),
			)
		})
	})

	When("creating a ClusterAdmissionPolicy with a PolicyServer assigned but not running yet", func() {
		var (
			policyName       = newName("scheduled-policy")
			policyServerName = newName("policy-server")
		)

		It("should set the policy status to scheduled", func() {
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(haveSucceededOrAlreadyExisted())

			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
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
			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})
	})
})
