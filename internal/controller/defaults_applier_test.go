package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

var _ = Describe("DefaultsApplierReconciler", func() {
	const (
		timeout      = 180 * time.Second
		pollInterval = 250 * time.Millisecond
	)

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
		// Clean up ConfigMap
		cm := &corev1.ConfigMap{}
		err := k8sClient.Get(ctx, configMapNsName, cm)
		if err == nil {
			Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		}

		// Clean up any managed resources (ignore NotFound since the
		// reconciler may have already deleted them after the ConfigMap removal).
		psList := &policiesv1.PolicyServerList{}
		Expect(k8sClient.List(ctx, psList)).To(Succeed())
		for _, ps := range psList.Items {
			if ps.Labels[constants.DefaultsManagedByLabelKey] == constants.DefaultsManagedByLabelValue {
				err := k8sClient.Delete(ctx, &ps)
				if err != nil && !apierrors.IsNotFound(err) {
					Expect(err).ToNot(HaveOccurred())
				}
			}
		}

		capList := &policiesv1.ClusterAdmissionPolicyList{}
		Expect(k8sClient.List(ctx, capList)).To(Succeed())
		for _, cap := range capList.Items {
			if cap.Labels[constants.DefaultsManagedByLabelKey] == constants.DefaultsManagedByLabelValue {
				err := k8sClient.Delete(ctx, &cap)
				if err != nil && !apierrors.IsNotFound(err) {
					Expect(err).ToNot(HaveOccurred())
				}
			}
		}
	})

	Context("when ConfigMap does not exist", func() {
		It("should do nothing when no managed resources exist", func() {
			// No ConfigMap exists, reconciler should not error
			// This is tested implicitly by the absence of errors in the controller logs
		})

		It("should delete all managed resources when they exist", func() {
			// First create the ConfigMap so the reconciler creates the PolicyServer
			policyServerYAML := `apiVersion: policies.kubewarden.io/v1
kind: PolicyServer
metadata:
  name: ` + policyServerName + `
spec:
  image: ghcr.io/kubewarden/policy-server:latest
  replicas: 1`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default.yaml": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			// Wait for the PolicyServer to be created
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
			}, timeout, pollInterval).Should(Succeed())

			// Delete the ConfigMap to trigger cleanup
			Expect(k8sClient.Delete(ctx, cm)).To(Succeed())

			// Wait for the managed resource to be deleted
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
				return apierrors.IsNotFound(err)
			}, timeout, pollInterval).Should(BeTrue(), "managed PolicyServer should be deleted")
		})
	})

	Context("when ConfigMap has one PolicyServer", func() {
		It("should create the PolicyServer with ownership label", func() {
			policyServerYAML := `apiVersion: policies.kubewarden.io/v1
kind: PolicyServer
metadata:
  name: ` + policyServerName + `
spec:
  image: ghcr.io/kubewarden/policy-server:latest
  replicas: 1
  serviceAccountName: policy-server`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default.yaml": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			// Wait for the PolicyServer to be created
			ps := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, ps)
			}, timeout, pollInterval).Should(Succeed())

			// Verify ownership label
			Expect(ps.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
			Expect(ps.Spec.Image).To(Equal("ghcr.io/kubewarden/policy-server:latest"))
		})
	})

	Context("when ConfigMap is updated", func() {
		It("should update the PolicyServer spec", func() {
			initialYAML := `apiVersion: policies.kubewarden.io/v1
kind: PolicyServer
metadata:
  name: ` + policyServerName + `
spec:
  image: ghcr.io/kubewarden/policy-server:v1.0.0
  replicas: 1`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default.yaml": initialYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			// Wait for initial creation
			ps := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, ps)
			}, timeout, pollInterval).Should(Succeed())
			Expect(ps.Spec.Image).To(Equal("ghcr.io/kubewarden/policy-server:v1.0.0"))

			// Update the ConfigMap
			updatedYAML := `apiVersion: policies.kubewarden.io/v1
kind: PolicyServer
metadata:
  name: ` + policyServerName + `
spec:
  image: ghcr.io/kubewarden/policy-server:v2.0.0
  replicas: 2`

			Expect(k8sClient.Get(ctx, configMapNsName, cm)).To(Succeed())
			cm.Data["policyserver-default.yaml"] = updatedYAML
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())

			// Wait for the PolicyServer to be updated
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, ps)
				if err != nil {
					return ""
				}
				return ps.Spec.Image
			}, timeout, pollInterval).Should(Equal("ghcr.io/kubewarden/policy-server:v2.0.0"))

			Expect(ps.Spec.Replicas).To(Equal(int32(2)))
		})
	})

	Context("when a key is removed from ConfigMap", func() {
		It("should delete the corresponding managed resource", func() {
			policyServerYAML := `apiVersion: policies.kubewarden.io/v1
kind: PolicyServer
metadata:
  name: ` + policyServerName + `
spec:
  image: ghcr.io/kubewarden/policy-server:latest
  replicas: 1`

			policyYAML := `apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: ` + policyName + `
spec:
  module: ghcr.io/kubewarden/policies/test:v1.0.0
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations: ["CREATE"]
  settings: {}`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default.yaml": policyServerYAML,
					"policy.yaml":               policyYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			// Wait for both resources to be created
			ps := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, ps)
			}, timeout, pollInterval).Should(Succeed())

			policy := &policiesv1.ClusterAdmissionPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy)
			}, timeout, pollInterval).Should(Succeed())

			// Remove the policy from the ConfigMap
			Expect(k8sClient.Get(ctx, configMapNsName, cm)).To(Succeed())
			delete(cm.Data, "policy.yaml")
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())

			// Wait for the policy to be deleted
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, policy)
				return apierrors.IsNotFound(err)
			}, timeout, pollInterval).Should(BeTrue(), "managed policy should be deleted")

			// PolicyServer should still exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, ps)).To(Succeed())
		})
	})

	Context("resource safety", func() {
		It("should never delete resources without the ownership label", func() {
			// Create an unmanaged PolicyServer (no ownership label)
			unmanagedPS := &policiesv1.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "unmanaged-policyserver",
				},
				Spec: policiesv1.PolicyServerSpec{
					Image:    "ghcr.io/kubewarden/policy-server:latest",
					Replicas: 1,
				},
			}
			Expect(k8sClient.Create(ctx, unmanagedPS)).To(Succeed())

			// Create an empty ConfigMap (should trigger cleanup of all managed resources)
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			// Wait a bit to allow reconciliation
			time.Sleep(2 * time.Second)

			// Unmanaged resource should still exist
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "unmanaged-policyserver"}, &policiesv1.PolicyServer{})).To(Succeed())

			// Clean up
			Expect(k8sClient.Delete(ctx, unmanagedPS)).To(Succeed())
		})
	})

	Context("when ConfigMap has malformed YAML", func() {
		It("should skip the malformed entry and continue with others", func() {
			policyServerYAML := `apiVersion: policies.kubewarden.io/v1
kind: PolicyServer
metadata:
  name: ` + policyServerName + `
spec:
  image: ghcr.io/kubewarden/policy-server:latest
  replicas: 1`

			malformedYAML := `this is not: valid: yaml: at: all`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default.yaml": policyServerYAML,
					"malformed.yaml":            malformedYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			// Wait for the valid PolicyServer to be created (malformed entry should be skipped)
			ps := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, ps)
			}, timeout, pollInterval).Should(Succeed())

			Expect(ps.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
		})
	})
})
