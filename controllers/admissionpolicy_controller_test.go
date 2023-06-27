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

package controllers

import (
	"fmt"
	"time"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Given an AdmissionPolicy", func() {
	BeforeEach(func() {
		someNamespace := someNamespace.DeepCopy()
		Expect(
			k8sClient.Create(ctx, someNamespace),
		).To(HaveSucceededOrAlreadyExisted())
	})
	When("it does not have a status set", func() {
		Context("and it is not deleted", func() {
			Context("and it has an empty policy server set on its spec", func() {
				var (
					policyNamespace = someNamespace.Name
					policyName      = "unscheduled-policy"
				)
				BeforeEach(func() {
					Expect(
						k8sClient.Create(ctx, admissionPolicyWithPolicyServerName(policyName, "")),
					).To(HaveSucceededOrAlreadyExisted())
				})
				It(fmt.Sprintf("should set its policy status to %q", policiesv1.PolicyStatusUnscheduled), func() {
					Eventually(func(g Gomega) (*policiesv1.AdmissionPolicy, error) {
						return getFreshAdmissionPolicy(policyNamespace, policyName)
					}).Should(
						WithTransform(
							func(admissionPolicy *policiesv1.AdmissionPolicy) policiesv1.PolicyStatusEnum {
								return admissionPolicy.Status.PolicyStatus
							},
							Equal(policiesv1.PolicyStatusUnscheduled),
						),
					)
				})
			})
			Context("and it has a non-empty policy server set on its spec", func() {
				var (
					policyNamespace  = someNamespace.Name
					policyName       = "scheduled-policy"
					policyServerName = "some-policy-server"
				)
				BeforeEach(func() {
					Expect(
						k8sClient.Create(ctx, admissionPolicyWithPolicyServerName(policyName, policyServerName)),
					).To(HaveSucceededOrAlreadyExisted())
				})
				It(fmt.Sprintf("should set its policy status to %q", policiesv1.PolicyStatusScheduled), func() {
					Eventually(func(g Gomega) (*policiesv1.AdmissionPolicy, error) {
						return getFreshAdmissionPolicy(policyNamespace, policyName)
					}).Should(
						WithTransform(
							func(admissionPolicy *policiesv1.AdmissionPolicy) policiesv1.PolicyStatusEnum {
								return admissionPolicy.Status.PolicyStatus
							},
							Equal(policiesv1.PolicyStatusScheduled),
						),
					)
				})
				Context("and the targeted policy server is created", func() {
					BeforeEach(func() {
						Expect(
							k8sClient.Create(ctx, policyServer(policyServerName)),
						).To(HaveSucceededOrAlreadyExisted())
					})
					It(fmt.Sprintf("should set its policy status to %q", policiesv1.PolicyStatusPending), func() {
						Eventually(func(g Gomega) (*policiesv1.AdmissionPolicy, error) {
							return getFreshAdmissionPolicy(policyNamespace, policyName)
						}, 30*time.Second, 250*time.Millisecond).Should(
							WithTransform(
								func(admissionPolicy *policiesv1.AdmissionPolicy) policiesv1.PolicyStatusEnum {
									return admissionPolicy.Status.PolicyStatus
								},
								Equal(policiesv1.PolicyStatusPending),
							),
						)
					})
				})
			})
		})
	})
})
