/*
Copyright 2026.

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

package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/certs"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

// k8sClient is the admin client used by test setup and assertions. It authenticates
// as system:masters (envtest default), which bypasses all RBAC enforcement. This is
// intentional: test authors need unrestricted access to create, inspect, and clean up
// arbitrary resources without fighting permissions.
//
// The manager's internal client (obtained via k8sManager.GetClient()) is deliberately
// different: it authenticates as the restricted "controller-manager" user and has only
// the permissions defined in the production RBAC roles. This mirrors what the
// controller's ServiceAccount receives in a real cluster installation via Helm. Using
// a restricted identity for the manager ensures that any missing RBAC permission
// causes a real authorization failure during tests rather than being silently bypassed.
var k8sClient client.Client

const (
	timeout              = 180 * time.Second
	pollInterval         = 250 * time.Millisecond
	consistencyTimeout   = 5 * time.Second
	deploymentsNamespace = "kubewarden-integration-tests"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	var ctx context.Context
	ctx, cancel := context.WithCancel(context.TODO())

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// restConfig authenticates as system:masters — the envtest superuser identity
	// that bypasses all RBAC. We use it only for k8sClient (test setup/assertions)
	// and as the base config (CA, host) when creating the restricted controller user.
	restConfig, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(restConfig).NotTo(BeNil())

	err = policiesv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	// k8sClient uses the admin (system:masters) config for full, unrestricted access.
	// Tests use this to create resources, wait for conditions, and inspect state.
	k8sClient, err = client.New(restConfig, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// The deploymentsNamespace must be created before the namespaced Role below.
	err = k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: deploymentsNamespace,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	// Create RBAC resources that mirror the production Helm chart permissions .
	// These are bound to the "controller-manager" user, which is the restricted
	// identity the manager will run as. By keeping the test RBAC in sync with
	// the production RBAC, any missing permission in the production roles will
	// surface as a test failure rather than a silent bypass.

	// ClusterRole grants permissions for cluster-scoped resources.
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "controller-manager-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{
					"mutatingwebhookconfigurations",
					"validatingwebhookconfigurations",
				},
				Verbs: []string{"create", "delete", "get", "list", "patch", "watch"},
			},
			{
				APIGroups: []string{"policies.kubewarden.io"},
				Resources: []string{
					"admissionpolicies",
					"admissionpolicygroups",
					"clusteradmissionpolicies",
					"clusteradmissionpolicygroups",
					"policyservers",
				},
				Verbs: []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
			{
				APIGroups: []string{"policies.kubewarden.io"},
				Resources: []string{
					"admissionpolicies/finalizers",
					"admissionpolicygroups/finalizers",
					"clusteradmissionpolicies/finalizers",
					"clusteradmissionpolicygroups/finalizers",
					"policyservers/finalizers",
				},
				Verbs: []string{"update"},
			},
			{
				APIGroups: []string{"policies.kubewarden.io"},
				Resources: []string{
					"admissionpolicies/status",
					"admissionpolicygroups/status",
					"clusteradmissionpolicies/status",
					"clusteradmissionpolicygroups/status",
					"policyservers/status",
				},
				Verbs: []string{"get", "patch", "update"},
			},
		},
	}
	err = k8sClient.Create(ctx, clusterRole)
	Expect(err).NotTo(HaveOccurred())

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "controller-manager-rolebinding",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "controller-manager-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: "controller-manager",
			},
		},
	}
	err = k8sClient.Create(ctx, clusterRoleBinding)
	Expect(err).NotTo(HaveOccurred())

	// Role grants permissions for namespace-scoped resources in deploymentsNamespace.
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "controller-manager-role",
			Namespace: deploymentsNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "secrets", "services"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"replicasets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"policy"},
				Resources: []string{"poddisruptionbudgets"},
				Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
			},
		},
	}
	err = k8sClient.Create(ctx, role)
	Expect(err).NotTo(HaveOccurred())

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "controller-manager-rolebinding",
			Namespace: deploymentsNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "controller-manager-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: "controller-manager",
			},
		},
	}
	err = k8sClient.Create(ctx, roleBinding)
	Expect(err).NotTo(HaveOccurred())

	// Create the restricted "controller-manager" user. This user is NOT a member
	// of system:masters, so Kubernetes RBAC is fully enforced for every API call
	// the manager makes. The credentials are backed by a client certificate issued
	// by the envtest CA; they carry no special privileges beyond the RBAC rules
	// created above.
	controllerUser, err := testEnv.AddUser(
		envtest.User{
			Name:   "controller-manager",
			Groups: []string{},
		},
		restConfig,
	)
	Expect(err).NotTo(HaveOccurred())

	// The manager runs under the restricted controllerUser identity.
	// The cache is configured to mirror the production setup (see cmd/controller/main.go):
	// - NamespacedCacheOptions restricts watches for namespace-scoped resources to
	//   deploymentsNamespace, matching the namespace-scoped Role permissions.
	//   Without this, controller-runtime would attempt cluster-wide watches on these
	//   types, which the namespace-scoped Role does not permit.
	// - DisableFor forces Get() on webhook configurations to bypass the informer
	//   cache and hit the API server directly, where RBAC is evaluated. Without
	//   this, controller-runtime serves Get() from the in-memory cache (populated
	//   via watch/list), so a missing "get" verb would never trigger a 403 error.
	k8sManager, err := ctrl.NewManager(controllerUser.Config(), ctrl.Options{
		Scheme: scheme.Scheme,
		Cache:  NamespacedCacheOptions(deploymentsNamespace),
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					&admissionregistrationv1.ValidatingWebhookConfiguration{},
					&admissionregistrationv1.MutatingWebhookConfiguration{},
				},
			},
		},
	})
	Expect(err).ToNot(HaveOccurred())

	err = (&AdmissionPolicyReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&ClusterAdmissionPolicyReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&AdmissionPolicyGroupReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&ClusterAdmissionPolicyGroupReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&PolicyServerReconciler{
		Client:                k8sManager.GetClient(),
		Scheme:                k8sManager.GetScheme(),
		DeploymentsNamespace:  deploymentsNamespace,
		ClientCAConfigMapName: clientCAConfigMapName,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	// Create the CA root secret
	caCertBytes, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	Expect(err).NotTo(HaveOccurred())
	err = k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CARootSecretName,
			Namespace: deploymentsNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.CARootCert:       caCertBytes,
			constants.CARootPrivateKey: caPrivateKey,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	// Create the client CA config map
	clientCACertBytes, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	Expect(err).NotTo(HaveOccurred())
	err = k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clientCAConfigMapName,
			Namespace: deploymentsNamespace,
		},
		Data: map[string]string{
			constants.ClientCACert: string(clientCACertBytes),
		},
	})
	Expect(err).NotTo(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err := k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()

	DeferCleanup(func() {
		By("tearing down the test environment")
		cancel()

		err := testEnv.Stop()
		Expect(err).ToNot(HaveOccurred(), "failed to tear down the test environment")
	})

	// Convert rest.Config in api.Config so we write it to bytes
	config := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"default": {
				Server:                   restConfig.Host,
				CertificateAuthorityData: restConfig.CAData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"default": {
				ClientCertificateData: restConfig.CertData,
				ClientKeyData:         restConfig.KeyData,
				Username:              restConfig.Username,
				Password:              restConfig.Password,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"default": {
				Cluster:  "default",
				AuthInfo: "default",
			},
		},
		CurrentContext: "default",
	}
	configBytes, err := clientcmd.Write(config)
	Expect(err).NotTo(HaveOccurred())

	return configBytes
}, func(configBytes []byte) {
	By("connecting to the test environment")
	if k8sClient != nil {
		return
	}

	config, err := clientcmd.Load(configBytes)
	Expect(err).NotTo(HaveOccurred())
	restConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
	restConfig.QPS = 1000.0
	restConfig.Burst = 2000.0
	Expect(err).NotTo(HaveOccurred())

	err = policiesv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(restConfig, client.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).NotTo(HaveOccurred())
})
