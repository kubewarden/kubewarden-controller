package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testenv           env.Environment
	kindClusterName   string
	namespace         = "kubewarden"
	controllerImage   = "ghcr.io/kubewarden/kubewarden-controller:latest"
	auditScannerImage = "ghcr.io/kubewarden/audit-scanner:latest"
	policyServerImage = "ghcr.io/kubewarden/policy-server:latest"
)

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testenv = env.NewWithConfig(cfg)
	kindClusterName = envconf.RandomName("kubewarden-e2e-cluster", 32)
	releaseCRDsName := "kubewarden-crds"
	releaseControllerName := "kubewarden-controller"
	kubewardenCRDsChartPath := "../charts/kubewarden-crds"
	kubewardenControllerChartPath := "../charts/kubewarden-controller"

	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace, envfuncs.WithLabels(map[string]string{
			"pod-security.kubernetes.io/enforce":         "restricted",
			"pod-security.kubernetes.io/enforce-version": "latest",
		})),
		envfuncs.LoadImageToCluster(kindClusterName, controllerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, auditScannerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, policyServerImage, "--verbose", "--mode", "direct"),
		func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			// can be used to install additional helm charts or perform other custom setup
			manager := helm.New(cfg.KubeconfigFile())

			err := manager.RunInstall(helm.WithName(releaseCRDsName),
				helm.WithNamespace(cfg.Namespace()),
				helm.WithChart(kubewardenCRDsChartPath),
				helm.WithTimeout("1m"),
			)
			if err != nil {
				return ctx, fmt.Errorf("failed to install kubewarden-crds helm chart: %w", err)
			}

			err = manager.RunInstall(helm.WithName(releaseControllerName),
				helm.WithNamespace(cfg.Namespace()),
				helm.WithChart(kubewardenControllerChartPath),
				helm.WithWait(),
				helm.WithArgs(
					"--set", "image.tag=latest",
					"--set", "auditScanner.image.tag=latest",
					"--set", "logLevel=debug",
					"--set", "auditScanner.logLevel=debug",
				),
			)
			if err != nil {
				return ctx, fmt.Errorf("failed to install kubewarden-controller helm chart: %w", err)
			}

			// Wait explicitly for kubewarden-controller deployment to be ready
			err = waitForKubewardenControllerDeployment(ctx, cfg)
			if err != nil {
				return ctx, fmt.Errorf("failed to wait for kubewarden-controller deployment: %w", err)
			}

			return ctx, nil
		},
	)

	testenv.Finish(
		envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		envfuncs.DestroyCluster(kindClusterName),
	)

	os.Exit(testenv.Run(m))
}

// waitForKubewardenControllerDeployment waits for the kubewarden-controller deployment to be ready
func waitForKubewardenControllerDeployment(_ context.Context, cfg *envconf.Config) error {
	// Wait for the kubewarden-controller deployment to be available
	return wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "kubewarden-controller", Namespace: namespace}},
		appsv1.DeploymentAvailable,
		corev1.ConditionTrue,
	), wait.WithTimeout(5*time.Minute), wait.WithInterval(1*time.Second))
}
