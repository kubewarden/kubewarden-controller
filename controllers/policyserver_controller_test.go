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

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
)

var _ = Describe("PolicyServer controller", func() {
	policyServerName := newName("policy-server")

	BeforeEach(func() {
		Expect(
			k8sClient.Create(ctx, policyServerFactory(policyServerName)),
		).To(haveSucceededOrAlreadyExisted())
	})

	Context("it has no assigned policies", func() {
		It("should get its finalizer removed", func() {
			By("deleting the policy server")
			Expect(
				k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
			).To(Succeed())

			policyServer, err := getTestPolicyServer(policyServerName)

			Expect(err).ToNot(HaveOccurred())
			Expect(policyServer.Finalizers).ToNot(ContainElement(constants.KubewardenFinalizer))
		})
	})

	Context("it has assigned policies", func() {
		policyName := newName("policy")

		It("should delete assigned policies", func() {
			By("creating a policy and assigning it to the policy server")
			Expect(
				k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(haveSucceededOrAlreadyExisted())

			By("deleting the policy server")
			Expect(
				k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
			).To(Succeed())

			Eventually(func(g Gomega) (*policiesv1.ClusterAdmissionPolicy, error) {
				return getTestClusterAdmissionPolicy(policyName)
			}, timeout, pollInterval).ShouldNot(
				HaveField("DeletionTimestamp", BeNil()),
			)
		})

		It(fmt.Sprintf("should get its %q finalizer removed", constants.KubewardenFinalizer), func() {
			Eventually(func(g Gomega) (*policiesv1.PolicyServer, error) {
				return getTestPolicyServer(policyServerName)
			}, timeout, pollInterval).ShouldNot(
				HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
			)
		})
	})
})
