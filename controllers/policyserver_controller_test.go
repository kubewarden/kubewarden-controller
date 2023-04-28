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

	policiesv1 "github.com/kubewarden/kubewarden-controller/apis/policies/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

var _ = Describe("Given a PolicyServer", func() {
	var (
		policyServerName = "policy-server"
	)
	BeforeEach(func() {
		Expect(
			k8sClient.Create(ctx, policyServer(policyServerName)),
		).To(HaveSucceededOrAlreadyExisted())
	})
	When("it has no assigned policies", func() {
		Context("and it is deleted", func() {
			BeforeEach(func() {
				Expect(
					k8sClient.Delete(ctx, policyServer(policyServerName)),
				).To(Succeed())
			})
			It("should get its finalizer removed", func() {
				policyServer, err := getFreshPolicyServer(policyServerName)
				Expect(err).ToNot(HaveOccurred())
				Expect(policyServer).ToNot(
					WithTransform(func(policyServer *policiesv1.PolicyServer) []string {
						return policyServer.Finalizers
					}, ContainElement(constants.KubewardenFinalizer)),
				)
			})
		})
	})
	When("it has some assigned policies", func() {
		var (
			policyName = "some-policy"
		)
		BeforeEach(func() {
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyWithPolicyServerName(policyName, policyServerName)),
			).To(HaveSucceededOrAlreadyExisted())
		})
		Context("and it is deleted", func() {
			BeforeEach(func() {
				Expect(
					k8sClient.Delete(ctx, policyServer(policyServerName)),
				).To(Succeed())
			})
			It("should delete assigned policies", func() {
				Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
					return getFreshClusterAdmissionPolicy(policyName)
				}, 30*time.Second, 250*time.Millisecond).ShouldNot(
					WithTransform(
						func(clusterAdmissionPolicy *policiesv1.ClusterAdmissionPolicy) *metav1.Time {
							return clusterAdmissionPolicy.DeletionTimestamp
						},
						BeNil(),
					),
				)
			})
			It(fmt.Sprintf("should get its %q finalizer removed", constants.KubewardenFinalizer), func() {
				Eventually(func(g Gomega) (*policiesv1.PolicyServer, error) {
					return getFreshPolicyServer(policyServerName)
				}, 30*time.Second, 250*time.Millisecond).ShouldNot(
					WithTransform(func(policyServer *policiesv1.PolicyServer) []string {
						return policyServer.Finalizers
					}, ContainElement(constants.KubewardenFinalizer)),
				)
			})
		})
	})
})
