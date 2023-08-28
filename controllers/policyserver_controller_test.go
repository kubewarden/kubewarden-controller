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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

var _ = Describe("Given a PolicyServer", func() {
	var (
		policyServerName           = "policy-server"
		policyServerNameWithPrefix = policyServer(policyServerName).NameWithPrefix()
	)
	BeforeEach(func() {
		Expect(
			k8sClient.Create(ctx, policyServer(policyServerName)),
		).To(HaveSucceededOrAlreadyExisted())
	})
	Context("policy server certificate", func() {
		It("a secret for the policy server certificate should be created", func() {
			Eventually(func(g Gomega) ([]string, error) {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, secret)
				if err != nil {
					return []string{}, fmt.Errorf("failed to get policy server certificate secret: %s", err.Error())
				}
				dataKeys := []string{}
				for key := range secret.Data {
					dataKeys = append(dataKeys, key)
				}
				return dataKeys, nil
			}, 30*time.Second, 250*time.Millisecond).Should(Equal([]string{constants.PolicyServerTLSCert, constants.PolicyServerTLSKey}))
		})
		It("policy server should have a label with the latest certificate secret resource version", func() {
			Eventually(func(g Gomega) bool {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, secret)
				Expect(err).ToNot(HaveOccurred())

				policyServerDeploy := &appsv1.Deployment{}
				err = k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, policyServerDeploy)
				Expect(err).ToNot(HaveOccurred())

				return secret.GetResourceVersion() == policyServerDeploy.Spec.Template.Labels[constants.PolicyServerCertificateSecret]
			}, 30*time.Second, 250*time.Millisecond).Should(Equal(true))
		})
	})
	When("policy server secret is deleted", func() {
		BeforeEach(func() {
			Expect(
				k8sClient.Delete(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policyServerNameWithPrefix,
						Namespace: DeploymentsNamespace,
					},
				})).To(Succeed())
			Eventually(func(g Gomega) bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, &corev1.Secret{})
				return apierrors.IsNotFound(err)
			}, 30*time.Second, 250*time.Millisecond).Should(BeTrue())
		})
		It("it should be recreated", func() {
			Eventually(func(g Gomega) ([]string, error) {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, secret)
				if err != nil {
					return []string{}, fmt.Errorf("failed to get policy server certificate secret: %s", err.Error())
				}
				dataKeys := []string{}
				for key := range secret.Data {
					dataKeys = append(dataKeys, key)
				}
				return dataKeys, nil
			}, 30*time.Second, 250*time.Millisecond).Should(Equal([]string{constants.PolicyServerTLSCert, constants.PolicyServerTLSKey}))
		})
		It("policy server should have a label with the latest certificate secret resource version", func() {
			Eventually(func(g Gomega) (bool, error) {
				secret := &corev1.Secret{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, secret); err != nil {
					return false, fmt.Errorf("failed to get policy server certificate secret: $%s", err.Error())
				}

				policyServerDeploy := &appsv1.Deployment{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, policyServerDeploy); err != nil {
					return false, fmt.Errorf("failed to get policy server deployment: %s", err.Error())
				}

				return secret.GetResourceVersion() == policyServerDeploy.Spec.Template.Labels[constants.PolicyServerCertificateSecret], nil
			}, 30*time.Second, 250*time.Millisecond).Should(Equal(true))
		})
	})
	When("policy server is deleted", func() {
		It("its secret should be deleted as well", func() {
			Expect(
				k8sClient.Delete(ctx, policyServer(policyServerName)),
			).To(Succeed())

			Eventually(func(g Gomega) bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: policyServerNameWithPrefix, Namespace: DeploymentsNamespace}, &corev1.Secret{})
				return apierrors.IsNotFound(err)
			}, 30*time.Second, 250*time.Millisecond).Should(BeTrue())
		})
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
