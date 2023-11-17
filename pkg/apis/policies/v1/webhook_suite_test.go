/*


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

package v1

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	//+kubebuilder:scaffold:imports

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestWebhooks(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Webhook Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: false,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "..", "..", "config", "webhook")},
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	scheme := runtime.NewScheme()
	err = AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	err = admissionv1beta1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// start webhook server using Manager
	webhookInstallOptions := &testEnv.WebhookInstallOptions
	serverOptions := webhook.Options{
		Host:    webhookInstallOptions.LocalServingHost,
		Port:    webhookInstallOptions.LocalServingPort,
		CertDir: webhookInstallOptions.LocalServingCertDir,
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		WebhookServer:  webhook.NewServer(serverOptions),
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	Expect(err).NotTo(HaveOccurred())

	err = (&ClusterAdmissionPolicy{}).SetupWebhookWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	err = (&PolicyServer{}).SetupWebhookWithManager(mgr, "kubewarden")
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:webhook

	go func() {
		err = mgr.Start(ctx)
		if err != nil {
			Expect(err).NotTo(HaveOccurred())
		}
	}()

	// wait for the webhook server to get ready
	dialer := &net.Dialer{Timeout: time.Second}
	addrPort := fmt.Sprintf("%s:%d", webhookInstallOptions.LocalServingHost, webhookInstallOptions.LocalServingPort)
	Eventually(func() error {
		//nolint:gosec
		conn, err := tls.DialWithDialer(dialer, "tcp", addrPort, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return fmt.Errorf("failed polling webhook server: %w", err)
		}
		conn.Close()
		return nil
	}).Should(Succeed())
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func makeClusterAdmissionPolicyTemplate(name, namespace, policyServerName string, customRules []admissionregistrationv1.RuleWithOperations) *ClusterAdmissionPolicy {
	rules := customRules

	if rules == nil {
		rules = append(rules, admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"*/*"},
			},
		})
	}

	return &ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: ClusterAdmissionPolicySpec{
			PolicySpec: PolicySpec{
				PolicyServer: policyServerName,
				Settings: runtime.RawExtension{
					Raw: []byte("{}"),
				},
				Rules: rules,
			},
		},
	}
}

//nolint:dupl
func deleteClusterAdmissionPolicy(ctx context.Context, name, namespace string) {
	nsn := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	pol := &ClusterAdmissionPolicy{}
	err := k8sClient.Get(ctx, nsn, pol)
	if apierrors.IsNotFound(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())

	Expect(k8sClient.Delete(ctx, pol)).To(Succeed())

	// Remove finalizer
	err = k8sClient.Get(ctx, nsn, pol)
	Expect(err).NotTo(HaveOccurred())
	polUpdated := pol.DeepCopy()
	controllerutil.RemoveFinalizer(polUpdated, constants.KubewardenFinalizer)
	err = k8sClient.Update(ctx, polUpdated)
	if err != nil {
		fmt.Fprint(GinkgoWriter, err)
	}
	Expect(err).NotTo(HaveOccurred())

	Eventually(func() bool {
		err := k8sClient.Get(ctx, nsn, &ClusterAdmissionPolicy{})
		return apierrors.IsNotFound(err)
	}).Should(BeTrue())
}

func makePolicyServerTemplate(name, namespace string) *PolicyServer {
	return &PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: PolicyServerSpec{
			Image:    "image",
			Replicas: 1,
		},
	}
}

//nolint:dupl
func deletePolicyServer(ctx context.Context, name, namespace string) {
	nsn := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	pol := &PolicyServer{}
	err := k8sClient.Get(ctx, nsn, pol)
	if apierrors.IsNotFound(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())

	Expect(k8sClient.Delete(ctx, pol)).To(Succeed())

	// Remove finalizer
	err = k8sClient.Get(ctx, nsn, pol)
	Expect(err).NotTo(HaveOccurred())
	polUpdated := pol.DeepCopy()
	controllerutil.RemoveFinalizer(polUpdated, constants.KubewardenFinalizer)
	err = k8sClient.Update(ctx, polUpdated)
	if err != nil {
		fmt.Fprint(GinkgoWriter, err)
	}
	Expect(err).NotTo(HaveOccurred())

	Eventually(func() bool {
		err := k8sClient.Get(ctx, nsn, &ClusterAdmissionPolicy{})
		return apierrors.IsNotFound(err)
	}).Should(BeTrue())
}

// checkCreationSuccessfulWithRules checks that creating a ClusterAdmissionPolicy with the specified rules is successful
func checkCreationSuccessfulWithRules(policyName, namespace, policyServerName string, rulesArray []admissionregistrationv1.RuleWithOperations) {
	pol := makeClusterAdmissionPolicyTemplate(policyName, namespace, policyServerName, rulesArray)

	Expect(k8sClient.Create(ctx, pol)).To(Succeed())

	By("deleting the created ClusterAdmissionPolicy")
	deleteClusterAdmissionPolicy(ctx, policyName, namespace)
}

// checkUpdateSuccessfulWithRules checks that updating a created ClusterAdmissionPolicy with the specified rules is successful.
// It first creates a default ClusterAdmissionPolicy, then updates it to new rules that should succeed.
func checkUpdateSuccessfulWithRules(policyName, namespace, policyServerName string, rules []admissionregistrationv1.RuleWithOperations) {
	pol := makeClusterAdmissionPolicyTemplate(policyName, namespace, policyServerName, nil)
	Expect(k8sClient.Create(ctx, pol)).To(Succeed())

	pol.Spec.Rules = rules
	Expect(k8sClient.Update(ctx, pol)).To(Succeed())

	By("deleting the created ClusterAdmissionPolicy")
	deleteClusterAdmissionPolicy(ctx, policyName, namespace)
}

// checkCreationUnsuccessfulWithRules checks that creating a ClusterAdmissionPolicy with the specified rules is unsuccessful
func checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerName string, rules []admissionregistrationv1.RuleWithOperations) {
	pol := makeClusterAdmissionPolicyTemplate(policyName, namespace, policyServerName, rules)

	Expect(k8sClient.Create(ctx, pol)).ToNot(Succeed())
}

// checkUpdateSuccessfulWithRules checks that updating a created ClusterAdmissionPolicy with the specified rules is unsuccessful.
// It first creates a default ClusterAdmissionPolicy, then updates it to new rules that should not succeed.
func checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerName string, rules []admissionregistrationv1.RuleWithOperations) {
	pol := makeClusterAdmissionPolicyTemplate(policyName, namespace, policyServerName, nil)
	Expect(k8sClient.Create(ctx, pol)).To(Succeed())

	pol.Spec.Rules = rules
	Expect(k8sClient.Update(ctx, pol)).ToNot(Succeed())

	By("deleting the created ClusterAdmissionPolicy")
	deleteClusterAdmissionPolicy(ctx, policyName, namespace)
}

var _ = Describe("validate ClusterAdmissionPolicy webhook with ", func() {
	namespace := "default"
	policyServerFooName := "policy-server-foo"

	It("should accept creating ClusterAdmissionPolicy", func() {
		pol := makeClusterAdmissionPolicyTemplate("policy-test", namespace, policyServerFooName, nil)
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(pol), pol)
		if err != nil {
			fmt.Fprint(GinkgoWriter, err)
		}
		Expect(err).NotTo(HaveOccurred())

		By("checking default values")
		// Testing for PolicyStatus == "unscheduled" can't happen here, Status
		// subresources can't be defaulted
		Expect(pol.ObjectMeta.Finalizers).To(HaveLen(1))
		Expect(pol.ObjectMeta.Finalizers[0]).To(Equal(constants.KubewardenFinalizer))
		Expect(pol.Spec.PolicyServer).To(Equal(policyServerFooName))

		By("deleting the created ClusterAdmissionPolicy")
		deleteClusterAdmissionPolicy(ctx, "policy-test", namespace)
	})

	It("should deny updating ClusterAdmissionPolicy if policyServer name is changed", func() {
		pol := makeClusterAdmissionPolicyTemplate("policy-test2", namespace, "policy-server-bar", nil)
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())

		pol.Spec.PolicyServer = "policy-server-changed"
		Expect(k8sClient.Update(ctx, pol)).NotTo(Succeed())

		By("deleting the created ClusterAdmissionPolicy")
		deleteClusterAdmissionPolicy(ctx, "policy-test2", namespace)
	})

	Context("confirm valid values for the rules field", func() {
		When("an empty rules array is specified", func() {
			emptyObjectsRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)

			policyName := "policy-test-empty-rules-array"

			It("should fail to create a ClusterAdmissionPolicy", func() {
				checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyObjectsRulesArray)
			})

			It("should fail to update to a ClusterAdmissionPolicy", func() {
				checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyObjectsRulesArray)
			})
		})

		When("a rules array with empty objects is specified", func() {
			emptyObjectsRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
			emptyObjectsRulesArray = append(emptyObjectsRulesArray, admissionregistrationv1.RuleWithOperations{})

			policyName := "policy-test-empty-rules-object"

			It("should fail to create a ClusterAdmissionPolicy", func() {
				checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyObjectsRulesArray)
			})

			It("should fail to update to a ClusterAdmissionPolicy", func() {
				checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyObjectsRulesArray)
			})
		})

		When("a rules array with non-empty objects is specified", func() {
			When("the operations field is empty", func() {
				emptyOperationsRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyOperationsRulesArray = append(emptyOperationsRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
					},
				})

				policyName := "policy-test-empty-operations"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyOperationsRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyOperationsRulesArray)
				})
			})

			When("the operations field is null", func() {
				nullOperationsRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				nullOperationsRulesArray = append(nullOperationsRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: nil,
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
					},
				})

				policyName := "policy-test-null-operations-array"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, nullOperationsRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, nullOperationsRulesArray)
				})
			})

			When("the operations field contains the empty string", func() {
				emptyOperationsRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyOperationsRulesArray = append(emptyOperationsRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{""},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
					},
				})

				policyName := "policy-test-empty-string-operations"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyOperationsRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyOperationsRulesArray)
				})
			})

			When("the resources array has values but the apiVersions array does not", func() {
				emptyStringResourceRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyStringResourceRulesArray = append(emptyStringResourceRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{},
						Resources:   []string{"pods"},
					},
				})

				policyName := "policy-test-resource-array"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringResourceRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringResourceRulesArray)
				})
			})

			When("the apiVersions array has values but the resources array does not", func() {
				emptyStringResourceRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyStringResourceRulesArray = append(emptyStringResourceRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{},
					},
				})

				policyName := "policy-test-api-versions-array"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringResourceRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringResourceRulesArray)
				})
			})

			When("one of the values in the resources field is the empty string", func() {
				emptyStringResourceRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyStringResourceRulesArray = append(emptyStringResourceRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"", "pods"},
					},
				})

				policyName := "policy-test-empty-resource"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringResourceRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringResourceRulesArray)
				})
			})

			When("one of the values in the apiVersions field is the empty string", func() {
				emptyStringAPIVersionRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyStringAPIVersionRulesArray = append(emptyStringAPIVersionRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"", "v1"},
						Resources:   []string{"pods"},
					},
				})

				policyName := "policy-test-empty-api-versions"

				It("should fail to create a ClusterAdmissionPolicy", func() {
					checkCreationUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringAPIVersionRulesArray)
				})

				It("should fail to update to a ClusterAdmissionPolicy", func() {
					checkUpdateUnsuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringAPIVersionRulesArray)
				})
			})

			When("a rules array with valid objects and an empty API group is specified", func() {
				emptyStringAPIGroupsRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				emptyStringAPIGroupsRulesArray = append(emptyStringAPIGroupsRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
					},
				})

				policyName := "policy-test-empty-api-groups"

				It("should succeed creating a ClusterAdmissionPolicy", func() {
					checkCreationSuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringAPIGroupsRulesArray)
				})

				It("should succeed updating a ClusterAdmissionPolicy", func() {
					checkUpdateSuccessfulWithRules(policyName, namespace, policyServerFooName, emptyStringAPIGroupsRulesArray)
				})
			})

			When("a rules array with valid objects and a non-empty API group is specified", func() {
				nonEmptyAPIGroupRulesArray := make([]admissionregistrationv1.RuleWithOperations, 0)
				nonEmptyAPIGroupRulesArray = append(nonEmptyAPIGroupRulesArray, admissionregistrationv1.RuleWithOperations{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"apps"},
						APIVersions: []string{"v1"},
						Resources:   []string{"deployments"},
					},
				})

				policyName := "policy-test-non-empty-api-groups"

				It("should succeed creating a ClusterAdmissionPolicy", func() {
					checkCreationSuccessfulWithRules(policyName, namespace, policyServerFooName, nonEmptyAPIGroupRulesArray)
				})

				It("should succeed updating a ClusterAdmissionPolicy", func() {
					checkUpdateSuccessfulWithRules(policyName, namespace, policyServerFooName, nonEmptyAPIGroupRulesArray)
				})
			})
		})
	})
})

var _ = Describe("validate PolicyServer webhook with ", func() {
	namespace := "kubewarden"

	It("should add kubewarden finalizer when creating a PolicyServer", func() {
		pol := makePolicyServerTemplate("policyserver-test", namespace)
		Expect(k8sClient.Create(ctx, pol)).To(Succeed())
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(pol), pol)
		if err != nil {
			fmt.Fprint(GinkgoWriter, err)
		}
		Expect(err).NotTo(HaveOccurred())

		By("checking default values")
		Expect(pol.ObjectMeta.Finalizers).To(HaveLen(1))
		Expect(pol.ObjectMeta.Finalizers[0]).To(Equal(constants.KubewardenFinalizer))

		By("deleting the created PolicyServer")
		deletePolicyServer(ctx, "policyserver-test", namespace)
	})

	It("should deny creating a PolicyServer with an invalid name", func() {
		name := make([]byte, 64)
		for i := range name {
			name[i] = 'a'
		}

		pol := makePolicyServerTemplate(string(name), namespace)
		Expect(k8sClient.Create(ctx, pol)).ToNot(Succeed())
	})
})
