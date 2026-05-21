package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

func marshalPolicyServer(ps *policiesv1.PolicyServer) string {
	ps.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("PolicyServer"))
	data, err := sigsyaml.Marshal(ps)
	Expect(err).ToNot(HaveOccurred())
	return string(data)
}

func marshalClusterAdmissionPolicy(policy *policiesv1.ClusterAdmissionPolicy) string {
	policy.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("ClusterAdmissionPolicy"))
	data, err := sigsyaml.Marshal(policy)
	Expect(err).ToNot(HaveOccurred())
	return string(data)
}

var _ = Describe("DefaultsApplierReconciler", func() {
	var (
		ctx              context.Context
		configMapName    string
		configMapNsName  types.NamespacedName
		policyServerName string
		policyName       string
	)

	BeforeEach(func() {
		ctx = context.Background()
		configMapName = constants.DefaultDefaultsConfigMapName
		configMapNsName = types.NamespacedName{
			Name:      configMapName,
			Namespace: deploymentsNamespace,
		}
		policyServerName = "test-default-policyserver"
		policyName = "test-default-policy"
	})

	AfterEach(func() {
		cm := &corev1.ConfigMap{}
		err := k8sClient.Get(ctx, configMapNsName, cm)
		if err == nil {
			Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		}

		managedSelector := client.MatchingLabels{
			constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue,
		}
		for _, obj := range []client.Object{
			&policiesv1.PolicyServer{},
			&policiesv1.ClusterAdmissionPolicy{},
		} {
			Expect(k8sClient.DeleteAllOf(ctx, obj, managedSelector)).To(Succeed())
		}
	})

	Context("when ConfigMap does not exist", func() {
		It("should delete all managed resources when they exist", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
			}, timeout, pollInterval).Should(Succeed())

			Expect(k8sClient.Delete(ctx, cm)).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
				return apierrors.IsNotFound(err)
			}, timeout, pollInterval).Should(BeTrue(), "managed PolicyServer should be deleted")
		})
	})

	Context("when ConfigMap has one PolicyServer", func() {
		It("should create the PolicyServer with ownership label", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPS := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
			}, timeout, pollInterval).Should(Succeed())

			Expect(createdPS.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
			Expect(createdPS.Spec.Image).To(Equal(ps.Spec.Image))
		})
	})

	Context("when ConfigMap is updated", func() {
		It("should update the PolicyServer spec", func() {
			initialPS := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			initialPS.Spec.Image = "ghcr.io/kubewarden/policy-server:v1.0.0"
			initialYAML := marshalPolicyServer(initialPS)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": initialYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPS := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
			}, timeout, pollInterval).Should(Succeed())
			Expect(createdPS.Spec.Image).To(Equal("ghcr.io/kubewarden/policy-server:v1.0.0"))

			updatedPS := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			updatedPS.Spec.Image = "ghcr.io/kubewarden/policy-server:v2.0.0"
			updatedYAML := marshalPolicyServer(updatedPS)

			Expect(k8sClient.Get(ctx, configMapNsName, cm)).To(Succeed())
			cm.Data["policyserver-default"] = updatedYAML
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())

			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
				if err != nil {
					return ""
				}
				return createdPS.Spec.Image
			}, timeout, pollInterval).Should(Equal("ghcr.io/kubewarden/policy-server:v2.0.0"))
		})
	})

	Context("when a key is removed from ConfigMap", func() {
		It("should delete the corresponding managed resource", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			clusterPolicy := policiesv1.NewClusterAdmissionPolicyFactory().WithName(policyName).WithoutFinalizers().Build()
			policyYAML := marshalClusterAdmissionPolicy(clusterPolicy)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
					"policy":               policyYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
			}, timeout, pollInterval).Should(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, &policiesv1.ClusterAdmissionPolicy{})
			}, timeout, pollInterval).Should(Succeed())

			Expect(k8sClient.Get(ctx, configMapNsName, cm)).To(Succeed())
			delete(cm.Data, "policy")
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, &policiesv1.ClusterAdmissionPolicy{})
				return apierrors.IsNotFound(err)
			}, timeout, pollInterval).Should(BeTrue(), "managed policy should be deleted")

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})).To(Succeed())
		})
	})

	Context("resource safety", func() {
		It("should never delete resources without the ownership label", func() {
			unmanagedPS := policiesv1.NewPolicyServerFactory().WithName("unmanaged-policyserver").WithoutFinalizers().Build()
			Expect(k8sClient.Create(ctx, unmanagedPS)).To(Succeed())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: unmanagedPS.Name}, &policiesv1.PolicyServer{})
			}, consistencyTimeout, pollInterval).Should(Succeed())

			Expect(k8sClient.Delete(ctx, unmanagedPS)).To(Succeed())
		})
	})

	Context("when ConfigMap has malformed YAML", func() {
		It("should skip the malformed entry and continue with others", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			malformedYAML := `this is not: valid: yaml: at: all`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
					"malformed":            malformedYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPS := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
			}, timeout, pollInterval).Should(Succeed())

			Expect(createdPS.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
		})
	})
})
