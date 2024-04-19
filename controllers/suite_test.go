/*
Copyright 2021.

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
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	cfg          *rest.Config //nolint
	k8sClient    client.Client
	testEnv      *envtest.Environment
	ctx          context.Context
	cancel       context.CancelFunc
	reconciler   admission.Reconciler
	k3sContainer *k3s.K3sContainer
)

const (
	DeploymentsNamespace = "kubewarden-integration-tests"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	k3sTestcontainerVersion, ok := os.LookupEnv("K3S_TESTCONTAINER_VERSION")
	if !ok {
		k3sTestcontainerVersion = "latest"
	}

	var err error
	k3sContainer, err = k3s.RunContainer(ctx,
		testcontainers.WithImage("docker.io/rancher/k3s:"+k3sTestcontainerVersion),
	)
	Expect(err).NotTo(HaveOccurred())

	kubeConfigYaml, err := k3sContainer.GetKubeConfig(ctx)
	Expect(err).NotTo(HaveOccurred())

	restcfg, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYaml)
	Expect(err).NotTo(HaveOccurred())

	trueValue := true
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		Config:                restcfg,
		UseExistingCluster:    &trueValue,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = policiesv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	reconciler = admission.Reconciler{
		Client:               k8sManager.GetClient(),
		APIReader:            k8sManager.GetClient(),
		Log:                  ctrl.Log.WithName("reconciler"),
		DeploymentsNamespace: DeploymentsNamespace,
	}

	err = (&AdmissionPolicyReconciler{
		Client:     k8sManager.GetClient(),
		Scheme:     k8sManager.GetScheme(),
		Reconciler: reconciler,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&ClusterAdmissionPolicyReconciler{
		Client:     k8sManager.GetClient(),
		Scheme:     k8sManager.GetScheme(),
		Reconciler: reconciler,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&PolicyServerReconciler{
		Client:     k8sManager.GetClient(),
		Scheme:     k8sManager.GetScheme(),
		Reconciler: reconciler,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	// Create the integration tests deployments namespace
	err = k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: DeploymentsNamespace,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()
})

var _ = AfterSuite(func() {
	// When running the suite muiltply times, canceling the context
	// is not enough to stop the container in time. We need to terminate it.
	// Otherwise, the next run may fail in the container initialization.
	By("terminate the k3s container")
	err := k3sContainer.Terminate(ctx)
	Expect(err).NotTo(HaveOccurred())

	cancel()
	By("tearing down the test environment")

	err = testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())

})
