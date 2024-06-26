/*
copyright 2022.

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
	"encoding/json"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"      //nolint:revive
	. "github.com/onsi/gomega"         //nolint:revive
	. "github.com/onsi/gomega/gstruct" //nolint:revive
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
)

var _ = Describe("PolicyServer controller", func() {
	var policyServerName string

	BeforeEach(func() {
		policyServerName = newName("policy-server")
	})

	When("deleting a PolicyServer", func() {
		BeforeEach(func() {
			createPolicyServerAndWaitForItsService(policyServerFactory(policyServerName))
		})

		Context("with no assigned policies", func() {
			It("should get its finalizer removed", func() {
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})

			It("should get its old not domain-qualified finalizer removed", func() {
				Eventually(func() error {
					policyServer, err := getTestPolicyServer(policyServerName)
					if err != nil {
						return err
					}
					controllerutil.AddFinalizer(policyServer, constants.KubewardenFinalizerPre114)
					return k8sClient.Update(ctx, policyServer)
				}, timeout, pollInterval).Should(Succeed())

				Eventually(func() error {
					policyServer, err := getTestPolicyServer(policyServerName)
					if err != nil {
						return err
					}
					if controllerutil.ContainsFinalizer(policyServer, constants.KubewardenFinalizerPre114) {
						return nil
					}
					return errors.New("finalizer not found")
				}, timeout, pollInterval).Should(Succeed())

				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizerPre114)),
				)
			})

			It("policy server resources should be gone after it being deleted", func() {
				// It's necessary remove the test finalizer to make the
				// Kubernetes garbage collector to remove the resources
				Eventually(func() error {
					policyServer, err := getTestPolicyServer(policyServerName)
					if err != nil {
						return err
					}
					controllerutil.RemoveFinalizer(policyServer, IntegrationTestsFinalizer)
					return reconciler.Client.Update(ctx, policyServer)
				}).Should(Succeed())

				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() error {
					_, err := getTestPolicyServer(policyServerName)
					return err
				}, timeout, pollInterval).Should(notFound())

				Eventually(func() error {
					_, err := getTestPolicyServerService(policyServerName)
					return err
				}, timeout, pollInterval).Should(notFound())

				Eventually(func() error {
					_, err := getTestPolicyServerSecret(policyServerName)
					return err
				}, timeout, pollInterval).Should(notFound())

				Eventually(func() error {
					_, err := getTestPolicyServerDeployment(policyServerName)
					return err
				}, timeout, pollInterval).Should(notFound())

				Eventually(func() error {
					_, err := getTestPolicyServerConfigMap(policyServerName)
					return err
				}, timeout, pollInterval).Should(notFound())
			})
		})

		Context("with assigned policies", func() {
			var policyName string

			BeforeEach(func() {
				policyName = newName("policy")
				Expect(
					k8sClient.Create(ctx, clusterAdmissionPolicyFactory(policyName, policyServerName, false)),
				).To(Succeed())
				Eventually(func() error {
					_, err := getTestClusterAdmissionPolicy(policyName)
					return err
				}, timeout, pollInterval).Should(Succeed())
				Expect(
					getTestPolicyServerService(policyServerName),
				).To(
					HaveField("DeletionTimestamp", BeNil()),
				)
			})

			It("should delete assigned policies", func() {
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(policyName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("DeletionTimestamp", BeNil()),
				)
			})

			It("should get its old not domain-qualidied finalizer removed from policies", func() {
				Eventually(func() error {
					policy, err := getTestClusterAdmissionPolicy(policyName)
					if err != nil {
						return err
					}
					controllerutil.AddFinalizer(policy, constants.KubewardenFinalizerPre114)
					return k8sClient.Update(ctx, policy)
				}, timeout, pollInterval).Should(Succeed())
				Eventually(func() error {
					policy, err := getTestClusterAdmissionPolicy(policyName)
					if err != nil {
						return err
					}
					if controllerutil.ContainsFinalizer(policy, constants.KubewardenFinalizerPre114) {
						return nil
					}
					return errors.New("old finalizer not found")
				}, timeout, pollInterval).Should(Succeed())

				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(policyName)
				}, timeout, pollInterval).Should(And(
					HaveField("DeletionTimestamp", Not(BeNil())),
					HaveField("Finalizers", Not(ContainElement(constants.KubewardenFinalizer))),
					HaveField("Finalizers", Not(ContainElement(constants.KubewardenFinalizerPre114))),
					HaveField("Finalizers", ContainElement(IntegrationTestsFinalizer)),
				))
			})

			It("should not delete its managed resources until all the scheduled policies are gone", func() {
				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
					return getTestClusterAdmissionPolicy(policyName)
				}).Should(And(
					HaveField("DeletionTimestamp", Not(BeNil())),
					HaveField("Finalizers", Not(ContainElement(constants.KubewardenFinalizer))),
					HaveField("Finalizers", ContainElement(IntegrationTestsFinalizer)),
				))

				Eventually(func() error {
					_, err := getTestPolicyServerService(policyServerName)
					return err
				}).Should(Succeed())
			})

			It(fmt.Sprintf("should get its %q finalizer removed", constants.KubewardenFinalizer), func() {
				Eventually(func() error {
					policy, err := getTestClusterAdmissionPolicy(policyName)
					if err != nil {
						return err
					}
					controllerutil.RemoveFinalizer(policy, IntegrationTestsFinalizer)
					return reconciler.Client.Update(ctx, policy)
				}).Should(Succeed())

				Expect(
					k8sClient.Delete(ctx, policyServerFactory(policyServerName)),
				).To(Succeed())

				// wait for the reconciliation loop of the ClusterAdmissionPolicy to remove the resource
				Eventually(func() error {
					_, err := getTestClusterAdmissionPolicy(policyName)
					return err
				}, timeout, pollInterval).ShouldNot(Succeed())

				Eventually(func() (*policiesv1.PolicyServer, error) {
					return getTestPolicyServer(policyServerName)
				}, timeout, pollInterval).ShouldNot(
					HaveField("Finalizers", ContainElement(constants.KubewardenFinalizer)),
				)
			})
		})
	})

	When("creating a PolicyServer", func() {
		It("should use the policy server affinity configuration in the policy server deployment", func() {
			policyServer := policyServerFactory(policyServerName)
			policyServer.Spec.Affinity = corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "label",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"nodename"},
									},
								},
							},
						},
					},
				},
			}
			createPolicyServerAndWaitForItsService(policyServer)
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Expect(deployment.Spec.Template.Spec.Affinity).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"NodeAffinity": PointTo(MatchFields(IgnoreExtras, Fields{
					"RequiredDuringSchedulingIgnoredDuringExecution": PointTo(MatchFields(IgnoreExtras, Fields{
						"NodeSelectorTerms": ContainElement(MatchFields(IgnoreExtras, Fields{
							"MatchExpressions": ContainElement(MatchAllFields(Fields{
								"Key":      Equal("label"),
								"Operator": Equal(corev1.NodeSelectorOpIn),
								"Values":   Equal([]string{"nodename"}),
							})),
						})),
					})),
				})),
			})))
		})

		It("should create policy server deployment with some default configuration", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			By("checking the deployment container security context")
			Expect(deployment.Spec.Template.Spec.Containers).Should(ContainElement(MatchFields(IgnoreExtras, Fields{
				"SecurityContext": PointTo(MatchFields(IgnoreExtras, Fields{
					"RunAsNonRoot":             PointTo(BeTrue()),
					"AllowPrivilegeEscalation": PointTo(BeFalse()),
					"Privileged":               PointTo(BeFalse()),
					"ReadOnlyRootFilesystem":   PointTo(BeTrue()),
					"Capabilities": PointTo(MatchAllFields(Fields{
						"Add":  BeNil(),
						"Drop": Equal([]corev1.Capability{"all"}),
					})),
					"SELinuxOptions": BeNil(),
					"WindowsOptions": BeNil(),
					"RunAsUser":      BeNil(),
					"RunAsGroup":     BeNil(),
					"ProcMount":      BeNil(),
					"SeccompProfile": BeNil(),
				})),
			})))
			By("checking the deployment pod security context")
			Expect(deployment.Spec.Template.Spec.SecurityContext).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"SELinuxOptions":      BeNil(),
				"WindowsOptions":      BeNil(),
				"RunAsUser":           BeNil(),
				"RunAsGroup":          BeNil(),
				"RunAsNonRoot":        BeNil(),
				"SupplementalGroups":  BeNil(),
				"FSGroup":             BeNil(),
				"Sysctls":             BeNil(),
				"FSGroupChangePolicy": BeNil(),
				"SeccompProfile":      BeNil(),
			})))

			By("checking the deployment affinity")
			Expect(deployment.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should create the policy server deployment and use the user defined security contexts", func() {
			policyServer := policyServerFactory(policyServerName)
			runAsUser := int64(1000)
			privileged := true
			runAsNonRoot := false
			policyServer.Spec.SecurityContexts = policiesv1.PolicyServerSecurity{
				Container: &corev1.SecurityContext{
					RunAsUser:    &runAsUser,
					Privileged:   &privileged,
					RunAsNonRoot: &runAsNonRoot,
				},
				Pod: &corev1.PodSecurityContext{
					RunAsUser:    &runAsUser,
					RunAsNonRoot: &runAsNonRoot,
				},
			}
			createPolicyServerAndWaitForItsService(policyServer)
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Expect(deployment.Spec.Template.Spec.Containers).Should(ContainElement(MatchFields(IgnoreExtras, Fields{
				"SecurityContext": PointTo(MatchFields(IgnoreExtras, Fields{
					"RunAsNonRoot":             PointTo(BeFalse()),
					"AllowPrivilegeEscalation": BeNil(),
					"Privileged":               PointTo(BeTrue()),
					"ReadOnlyRootFilesystem":   BeNil(),
					"Capabilities":             BeNil(),
					"SELinuxOptions":           BeNil(),
					"WindowsOptions":           BeNil(),
					"RunAsUser":                PointTo(BeNumerically("==", 1000)),
					"RunAsGroup":               BeNil(),
					"ProcMount":                BeNil(),
					"SeccompProfile":           BeNil(),
				})),
			})))
			Expect(deployment.Spec.Template.Spec.SecurityContext).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"SELinuxOptions":      BeNil(),
				"WindowsOptions":      BeNil(),
				"RunAsUser":           PointTo(BeNumerically("==", 1000)),
				"RunAsGroup":          BeNil(),
				"RunAsNonRoot":        PointTo(BeFalse()),
				"SupplementalGroups":  BeNil(),
				"FSGroup":             BeNil(),
				"Sysctls":             BeNil(),
				"FSGroupChangePolicy": BeNil(),
				"SeccompProfile":      BeNil(),
			})))
		})

		It("should create the policy server configmap empty if no policies are assigned ", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			configmap, err := getTestPolicyServerConfigMap(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Expect(configmap).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: Equal("{}"),
					constants.PolicyServerConfigSourcesEntry:  Equal("{}"),
				}),
			})))
		})

		It("should create the policy server configmap with the assigned policies", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			policyName := newName("policy")
			policy := clusterAdmissionPolicyFactory(policyName, policyServerName, false)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			policiesMap := admission.PolicyConfigEntryMap{}
			policiesMap[policy.GetUniqueName()] = admission.PolicyServerConfigEntry{
				NamespacedName: types.NamespacedName{
					Namespace: policy.GetNamespace(),
					Name:      policy.GetName(),
				},
				URL:                   policy.GetModule(),
				PolicyMode:            string(policy.GetPolicyMode()),
				AllowedToMutate:       policy.IsMutating(),
				Settings:              policy.GetSettings(),
				ContextAwareResources: policy.GetContextAwareResources(),
			}
			policies, err := json.Marshal(policiesMap)
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() *corev1.ConfigMap {
				configMap, _ := getTestPolicyServerConfigMap(policyServerName)
				return configMap
			}, timeout, pollInterval).Should(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: MatchJSON(policies),
					constants.PolicyServerConfigSourcesEntry:  Equal("{}"),
				}),
			})))
		})

		It("should create the policy server configmap with the sources authorities", func() {
			policyServer := policyServerFactory(policyServerName)
			policyServer.Spec.InsecureSources = []string{"localhost:5000"}
			policyServer.Spec.SourceAuthorities = map[string][]string{
				"myprivateregistry:5000": {"cert1", "cert2"},
			}
			createPolicyServerAndWaitForItsService(policyServer)
			sourceAuthoriries := map[string][]map[string]string{}
			for uri, certificates := range policyServer.Spec.SourceAuthorities {
				certs := []map[string]string{}
				for _, cert := range certificates {
					certs = append(certs, map[string]string{
						"type": "Data",
						"data": cert,
					})
				}
				sourceAuthoriries[uri] = certs
			}
			sources, err := json.Marshal(map[string]interface{}{
				"insecure_sources":   policyServer.Spec.InsecureSources,
				"source_authorities": sourceAuthoriries,
			})
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() error {
				_, err := getTestPolicyServerConfigMap(policyServerName)
				return err
			}, timeout, pollInterval).Should(Succeed())
			configMap, err := getTestPolicyServerConfigMap(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Expect(configMap).To(PointTo(MatchFields(IgnoreExtras, Fields{
				"Data": MatchAllKeys(Keys{
					constants.PolicyServerConfigPoliciesEntry: Equal("{}"),
					constants.PolicyServerConfigSourcesEntry:  MatchJSON(sources),
				}),
			})))
		})

		It("should create PodDisruptionBudget when policy server has MinAvailable configuration set", func() {
			policyServer := policyServerFactory(policyServerName)
			minAvailable := intstr.FromInt(2)
			policyServer.Spec.MinAvailable = &minAvailable
			createPolicyServerAndWaitForItsService(policyServer)

			Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, &minAvailable, nil))
		})

		It("should create PodDisruptionBudget when policy server has MaxUnavailable configuration set", func() {
			policyServer := policyServerFactory(policyServerName)
			maxUnavailable := intstr.FromInt(2)
			policyServer.Spec.MaxUnavailable = &maxUnavailable
			createPolicyServerAndWaitForItsService(policyServer)

			Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))
		})

		It("should not create PodDisruptionBudget when policy server has no PDB configuration", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			Consistently(func() error {
				_, err := getPolicyServerPodDisruptionBudget(policyServerName)
				return err
			}, consistencyTimeout, pollInterval).ShouldNot(Succeed())
		})

		It("should create the PolicyServer pod with the limits and the requests", func() {
			policyServer := policyServerFactory(policyServerName)
			policyServer.Spec.Limits = corev1.ResourceList{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("1Gi"),
			}
			createPolicyServerAndWaitForItsService(policyServer)
			By("creating a deployment with limits and requests set")
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return err
				}
				Expect(deployment.Spec.Template.Spec.Containers[0].Resources.Limits).To(Equal(policyServer.Spec.Limits))
				return nil
			}, timeout, pollInterval).Should(Succeed())

			By("creating a pod with limit and request set")
			Eventually(func() error {
				pod, err := getTestPolicyServerPod(policyServerName)
				if err != nil {
					return err
				}

				Expect(pod.Spec.Containers[0].Resources.Limits).To(Equal(policyServer.Spec.Limits))

				By("setting the requests to the same value as the limits")
				Expect(pod.Spec.Containers[0].Resources.Requests).To(Equal(policyServer.Spec.Limits))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should create deployment with owner reference", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				Expect(deployment.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":        Equal(policyServer.GetUID()),
						"Name":       Equal(policyServer.GetName()),
						"Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						"APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should create configmap with owner reference", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			Eventually(func() error {
				configmap, err := getTestPolicyServerConfigMap(policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				Expect(configmap.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":        Equal(policyServer.GetUID()),
						"Name":       Equal(policyServer.GetName()),
						"Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						"APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should create service with owner reference", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			Eventually(func() error {
				service, err := getTestPolicyServerService(policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				Expect(service.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":        Equal(policyServer.GetUID()),
						"Name":       Equal(policyServer.GetName()),
						"Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						"APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should create the policy server secrets", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)

			Eventually(func() error {
				secret, err := getTestPolicyServerCASecret()
				if err != nil {
					return err
				}

				By("creating a secret containing the CA certificate and key")
				Expect(secret.Data).To(HaveKey(constants.PolicyServerCARootCACert))
				Expect(secret.Data).To(HaveKey(constants.PolicyServerCARootPemName))
				Expect(secret.Data).To(HaveKey(constants.PolicyServerCARootPrivateKeyCertName))

				return nil
			}).Should(Succeed())

			Eventually(func() error {
				secret, err := getTestPolicyServerSecret(policyServerName)
				if err != nil {
					return err
				}
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}

				By("creating a secret containing the TLS certificate and key")
				Expect(secret.Data).To(HaveKey(constants.PolicyServerTLSCert))
				Expect(secret.Data).To(HaveKey(constants.PolicyServerTLSKey))

				By("setting the secret owner reference")
				Expect(secret.OwnerReferences).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"UID":        Equal(policyServer.GetUID()),
						"Name":       Equal(policyServer.GetName()),
						"Kind":       Equal(policyServer.GetObjectKind().GroupVersionKind().Kind),
						"APIVersion": Equal(policyServer.GetObjectKind().GroupVersionKind().GroupVersion().String()),
					}),
				))
				return nil
			}).Should(Succeed())
		})

		It("should set the configMap version as a deployment annotation", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			configmap, err := getTestPolicyServerConfigMap(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return err
				}
				if deployment.GetAnnotations()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("deployment configmap version did not change")
				}
				if deployment.Spec.Template.GetLabels()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("pod configmap version did not change")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should update the configMap version after adding a policy", func() {
			policyServer := policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
			initalConfigMap, err := getTestPolicyServerConfigMap(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() error {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return err
				}
				if deployment.GetAnnotations()[constants.PolicyServerDeploymentConfigVersionAnnotation] != initalConfigMap.GetResourceVersion() {
					return errors.New("deployment configmap version did not change")
				}
				if deployment.Spec.Template.GetLabels()[constants.PolicyServerDeploymentConfigVersionAnnotation] != initalConfigMap.GetResourceVersion() {
					return errors.New("pod configmap version did not change")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())

			policyName := newName("validating-policy")
			policy := clusterAdmissionPolicyFactory(policyName, policyServerName, false)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			Eventually(func() error {
				configmap, err := getTestPolicyServerConfigMap(policyServerName)
				if err != nil {
					return err
				}
				if configmap.GetResourceVersion() == initalConfigMap.GetResourceVersion() {
					return errors.New("configmap version did not change")
				}
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return err
				}
				if deployment.GetAnnotations()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("deployment configmap version did not change")
				}
				if deployment.Spec.Template.GetLabels()[constants.PolicyServerDeploymentConfigVersionAnnotation] != configmap.GetResourceVersion() {
					return errors.New("pod configmap version did not change")
				}
				return nil
			}, timeout, pollInterval).Should(Succeed())
		})
	})

	When("updating the PolicyServer", func() {
		var policyServer *policiesv1.PolicyServer

		BeforeEach(func() {
			policyServer = policyServerFactory(policyServerName)
			createPolicyServerAndWaitForItsService(policyServer)
		})

		It("should create a PDB if the policy server definition is updated with a PodDisruptionBudget configuration", func() {
			Consistently(func() error {
				_, err := getPolicyServerPodDisruptionBudget(policyServerName)
				return err
			}, consistencyTimeout, pollInterval).ShouldNot(Succeed())

			By("updating the PolicyServer with a MaxAvailable PDB configuration")
			policyServer, err := getTestPolicyServer(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			maxUnavailable := intstr.FromInt(2)
			policyServer.Spec.MaxUnavailable = &maxUnavailable
			err = k8sClient.Update(ctx, policyServer)
			Expect(err).ToNot(HaveOccurred())

			By("creating a PodDisruptionBudget with a MaxUnavailable configuration")
			Eventually(func() *k8spoliciesv1.PodDisruptionBudget {
				pdb, _ := getPolicyServerPodDisruptionBudget(policyServerName)
				return pdb
			}, timeout, pollInterval).Should(policyServerPodDisruptionBudgetMatcher(policyServer, nil, &maxUnavailable))
		})

		It("should update deployment when policy server image change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldImage := deployment.Spec.Template.Spec.Containers[0].Image
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Image = "new-image"
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() string {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return ""
				}
				return deployment.Spec.Template.Spec.Containers[0].Image
			}).Should(And(Not(Equal(oldImage)), Equal("new-image")))
		})

		It("should update deployment when policy server replica size change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldReplica := deployment.Spec.Replicas
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Replicas = 2
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() int32 {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return 0
				}
				return *deployment.Spec.Replicas
			}).Should(And(Not(Equal(oldReplica)), Equal(int32(2))))
		})

		It("should update deployment when policy server service account change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldServiceAccount := deployment.Spec.Template.Spec.ServiceAccountName
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.ServiceAccountName = "new-service-account"
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() string {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return ""
				}
				return deployment.Spec.Template.Spec.ServiceAccountName
			}).Should(And(Not(Equal(oldServiceAccount)), Equal("new-service-account")))
		})

		It("should update deployment when policy server security context change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldSecurityContext := deployment.Spec.Template.Spec.SecurityContext
			newUser := int64(1000)
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.SecurityContexts.Pod = &corev1.PodSecurityContext{
					RunAsUser: &newUser,
				}
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() *corev1.PodSecurityContext {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.SecurityContext
			}).Should(And(PointTo(MatchFields(IgnoreExtras, Fields{
				"RunAsUser": PointTo(BeNumerically("==", newUser)),
			})), Not(PointTo(Equal(oldSecurityContext)))))
		})

		It("should update deployment when policy server affinity configuration change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldAffinity := deployment.Spec.Template.Spec.Affinity
			newAffinity := corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "label",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{"nodename"},
									},
								},
							},
						},
					},
				},
			}
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Affinity = newAffinity
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() *corev1.Affinity {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.Affinity
			}).Should(And(Not(PointTo(Equal(oldAffinity))), PointTo(Equal(newAffinity))))
		})

		It("should update deployment when policy server annotations change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldAnnotations := deployment.Spec.Template.Annotations
			newAnnotations := map[string]string{
				"new-annotation": "new-value",
			}
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Annotations = newAnnotations
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() map[string]string {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Annotations
			}).Should(And(Not(Equal(oldAnnotations)), Equal(newAnnotations)))
		})

		It("should update deployment when policy server resources limits change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldContainers := deployment.Spec.Template.Spec.Containers
			newResourceLimits := corev1.ResourceList{
				"cpu":    resource.MustParse("100m"),
				"memory": resource.MustParse("1Gi"),
			}
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Limits = newResourceLimits
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() []corev1.Container {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.Containers
			}).Should(And(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Resources": MatchFields(IgnoreExtras, Fields{
					"Limits": Equal(newResourceLimits),
				}),
			})), Not(Equal(oldContainers))))
		})

		It("should update deployment when policy server environment variables change", func() {
			deployment, err := getTestPolicyServerDeployment(policyServerName)
			Expect(err).ToNot(HaveOccurred())
			oldContainers := deployment.Spec.Template.Spec.Containers
			newEnvironmentVariable := corev1.EnvVar{
				Name:  "NEW_ENV",
				Value: "new-value",
			}
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Env = []corev1.EnvVar{newEnvironmentVariable}
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			Eventually(func() []corev1.Container {
				deployment, err := getTestPolicyServerDeployment(policyServerName)
				if err != nil {
					return nil
				}
				return deployment.Spec.Template.Spec.Containers
			}).Should(And(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Env": ContainElement(Equal(newEnvironmentVariable)),
			})), Not(Equal(oldContainers))))
		})

		It("should update the PolicyServer pod with the new requests when the requests are updated", func() {
			By("updating the PolicyServer requests")
			updatedRequestsResources := corev1.ResourceList{
				"cpu":    resource.MustParse("50m"),
				"memory": resource.MustParse("500Mi"),
			}
			Eventually(func() error {
				policyServer, err := getTestPolicyServer(policyServerName)
				if err != nil {
					return err
				}
				policyServer.Spec.Requests = updatedRequestsResources
				return k8sClient.Update(ctx, policyServer)
			}).Should(Succeed())

			By("updating the pod with the new requests")
			Eventually(func() (*corev1.Container, error) {
				pod, err := getTestPolicyServerPod(policyServerName)
				if err != nil {
					return nil, err
				}
				return &pod.Spec.Containers[0], nil
			}, timeout, pollInterval).Should(
				And(
					HaveField("Resources.Requests", Equal(updatedRequestsResources)),
					HaveField("Resources.Limits", Equal(policyServer.Spec.Limits)),
				),
			)
		})
	})
})
