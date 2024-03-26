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

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
)

var _ = Describe("PolicyServer controller", func() {
	Context("when starting with a new PolicyServer", func() {
		policyServerName := newName("policy-server")

		BeforeEach(func() {
			Expect(
				k8sClient.Create(ctx, policyServerFactory(policyServerName)),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServerService(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
		})

		Context("with no assigned policies", func() {
			It("should get its finalizer removed", func() {
				By("deleting the policy server")
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func(g Gomega) (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})

			AfterEach(func() {
				// It's necessary remove the test finalizer to make the
				// BeforeEach work as extected. Otherwise, the policy service
				// creation will not work as expected
				policyServer, err := getTestPolicyServer(policyServerName)
				Expect(err).Should(Succeed())
				controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)
				err = reconciler.Client.Update(ctx, policyServer)
				Expect(err).ToNot(HaveOccurred())
				Eventually(func(g Gomega) error {
					_, err := getTestPolicyServer(policyServerName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())
			})

		})

		Context("with assigned policies", Serial, func() {
			policyName := newName("policy")

			It("should delete assigned policies", func() {
				By("creating a policy and assigning it to the policy server")
				Expect(
					k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
				).To(haveSucceededOrAlreadyExisted())

				Expect(
					getTestPolicyServerService(policyServerName),
				).To(
					HaveField("DeletionTimestamp", BeNil()),
				)

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

			It("should not delete its managed resources until all the scheduled policies are gone", func() {
				By("having still policies pending deletion")
				Expect(
					getTestClusterAdmissionPolicy(policyName),
				).To(
					And(
						HaveField("DeletionTimestamp", Not(BeNil())),
						HaveField("Finalizers", Not(ContainElement(constants.KubewardenFinalizer))),
						HaveField("Finalizers", ContainElement(IntegrationTestsFinalizer)),
					),
				)

				Eventually(func(g Gomega) error {
					_, err := getTestPolicyServerService(policyServerName)
					return err
				}).Should(Succeed())
			})

			It(fmt.Sprintf("should get its %q finalizer removed", constants.KubewardenFinalizer), func() {
				By("not having policies assigned")
				policy, err := getTestClusterAdmissionPolicy(policyName)
				Expect(err).ToNot(HaveOccurred())

				controllerutil.RemoveFinalizer(policy, IntegrationTestsFinalizer)
				err = reconciler.Client.Update(ctx, policy)
				Expect(err).ToNot(HaveOccurred())

				// wait for the reconciliation loop of the ClusterAdmissionPolicy to remove the resource
				Eventually(func(g Gomega) error {
					_, err := getTestClusterAdmissionPolicy(policyName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())

				Eventually(func(g Gomega) error {
					_, err := getTestPolicyServerService(policyServerName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())

				Eventually(func(g Gomega) (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})
		})
	})

	Context("when starting policy server", func() {
		policyServerName := newName("policy-server")

		It("with MinAvailable PodDisruptionBudget configuration should create PDB", func() {
			minAvailable := intstr.FromInt(2)
			policyServer := policyServerFactory(policyServerName)
			policyServer.Spec.MinAvailable = &minAvailable
			// It's necessary remove the test finalizer to make the
			// policy service goes away.
			controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)

			Expect(
				k8sClient.Create(ctx, policyServer),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			Eventually(func(g Gomega) *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, &minAvailable, nil))

		})

		It("with MaxUnavailable PodDisruptionBudget configuration should create PDB", func() {
			maxUnavailable := intstr.FromInt(2)
			policyServer := policyServerFactory(policyServerName)
			policyServer.Spec.MaxUnavailable = &maxUnavailable
			// It's necessary remove the test finalizer to make the
			// policy service goes away.
			controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)

			Expect(
				k8sClient.Create(ctx, policyServer),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			Eventually(func(g Gomega) *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))
		})

		It("with no PodDisruptionBudget configuration should not create PDB", func() {
			policyServer := policyServerFactory(policyServerName)
			// It's necessary remove the test finalizer to make the
			// policy service goes away.
			controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)

			Expect(
				k8sClient.Create(ctx, policyServer),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			// Wait for the Service associated with the PolicyServer to be created.
			// The service reconciliation is after the PDB reconciliation.
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServerService(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			Consistently(func(g Gomega) error {
				_, err := getPolicyServerPodDisruptionBudget(policyServerName)
				return err
			}, 10*time.Second, pollInterval).ShouldNot(Succeed())
		})

		It("when update policy server PodDisruptionBudget configuration should create PDB", func() {
			policyServer := policyServerFactory(policyServerName)
			// It's necessary remove the test finalizer to make the
			// policy service goes away.
			controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)

			Expect(
				k8sClient.Create(ctx, policyServer),
			).To(haveSucceededOrAlreadyExisted())
			// Wait for the Service associated with the PolicyServer to be created
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			// Wait for the Service associated with the PolicyServer to be created.
			// The service reconciliation is after the PDB reconciliation.
			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServerService(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			Consistently(func(g Gomega) error {
				_, err := getPolicyServerPodDisruptionBudget(policyServerName)
				return err
			}, 10*time.Second, pollInterval).ShouldNot(Succeed())

			policyServer, err := getTestPolicyServer(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			maxUnavailable := intstr.FromInt(2)
			policyServer.Spec.MaxUnavailable = &maxUnavailable

			err = k8sClient.Update(ctx, policyServer)
			Expect(err).ToNot(HaveOccurred())

			Eventually(func(g Gomega) *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))

		})

		AfterEach(func() {
			policyServer, err := getTestPolicyServer(policyServerName)
			Expect(err).Should(Succeed())

			err = reconciler.Client.Delete(ctx, policyServer)
			Expect(err).ToNot(HaveOccurred())

			Eventually(func(g Gomega) error {
				_, err := getTestPolicyServer(policyServerName)
				return err
			}, timeout, pollInterval).ShouldNot(Succeed())

			Eventually(func(g Gomega) error {
				_, err := getPolicyServerPodDisruptionBudget(policyServerName)
				return err
			}, timeout, pollInterval).ShouldNot(Succeed())
		})
	})

})
