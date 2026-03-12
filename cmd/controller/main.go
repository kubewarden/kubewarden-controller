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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/api/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	"github.com/kubewarden/kubewarden-controller/internal/controller"
	"github.com/kubewarden/kubewarden-controller/internal/featuregates"
	"github.com/kubewarden/kubewarden-controller/internal/metrics"
	//+kubebuilder:scaffold:imports
)

// Kubewarden controller required permissions
//
//+kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete,namespace="kubewarden"
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete,namespace="kubewarden"
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch,namespace="kubewarden"
//+kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

//nolint:gochecknoglobals // Following the kubebuilder pattern
var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

type ManagerOptions struct {
	DeploymentsNamespace string
	EnableLeaderElection bool
	EnableMutualTLS      bool
	MetricsAddr          string
	ProbeAddr            string
}

type Configuration struct {
	AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool
	ClientCAConfigMapName                              string
	FeatureGateAdmissionWebhookMatchConditions         bool
	WebhookServiceName                                 string
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
	utilruntime.Must(policiesv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

//nolint:funlen // Avoid splitting the main function in multiple functions to avoid changing the retcode logic for metrics shutdown
func main() {
	retcode := 0
	defer func() { os.Exit(retcode) }()

	var mgrOpts ManagerOptions
	var config Configuration
	var enableMetrics bool
	var enableTracing bool
	var enableOtelSidecar bool
	var openTelemetryClientCertificateSecret string
	var openTelemetryCertificateSecret string

	flag.StringVar(&mgrOpts.MetricsAddr, "metrics-bind-address", ":8088", "The address the metric endpoint binds to.")
	flag.StringVar(&mgrOpts.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&mgrOpts.EnableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableMetrics, "enable-metrics", false,
		"Enable metrics collection for all Policy Servers and the Kubewarden Controller")
	flag.BoolVar(&enableTracing, "enable-tracing", false,
		"Enable tracing collection for all Policy Servers")
	flag.BoolVar(&enableOtelSidecar, "enable-otel-sidecar", false,
		"Enable OpenTelemetry sidecar in Policy Servers")
	flag.StringVar(&openTelemetryClientCertificateSecret, "opentelemetry-client-certificate-secret", "", "")
	flag.StringVar(&openTelemetryCertificateSecret, "opentelemetry-certificate-secret", "", "")
	flag.StringVar(&mgrOpts.DeploymentsNamespace,
		"deployments-namespace",
		"",
		"The namespace where the kubewarden resources will be created.")
	flag.StringVar(&config.WebhookServiceName,
		"webhook-service-name",
		"kubewarden-controller-webhook-service",
		"The name of the service that will be used to expose controller webhooks.")
	flag.BoolVar(&config.AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		"always-accept-admission-reviews-on-deployments-namespace",
		false,
		"Always accept admission reviews targeting the deployments-namespace.")
	flag.StringVar(&config.ClientCAConfigMapName, "client-ca-configmap-name", "", "The name of the ConfigMap containing the client CA certificate. If provided, mTLS will be enabled.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	mgrOpts.EnableMutualTLS = config.ClientCAConfigMapName != ""
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if enableMetrics {
		shutdown, err := metrics.New()
		if err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			retcode = 1
			return
		}
		setupLog.Info("Metrics initialized")

		// cleanly shutdown and flush telemetry on application exit
		defer func() {
			// Do not make the application hang when it is shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), constants.MetricsShutdownTimeout)
			defer cancel()

			if err := shutdown(ctx); err != nil { //nolint:govet // err is shadowed in purpose
				setupLog.Error(err, "Unable to shutdown telemetry")
				retcode = 1
				return
			}
		}()
	}

	mgr, err := setupManager(mgrOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		retcode = 1
		return
	}

	config.FeatureGateAdmissionWebhookMatchConditions, err = featuregates.CheckAdmissionWebhookMatchConditions(ctrl.GetConfigOrDie())
	if err != nil {
		setupLog.Error(err, "unable to check for feature gate AdmissionWebhookMatchConditions")
	}

	otelConfiguration := controller.TelemetryConfiguration{
		MetricsEnabled:              enableMetrics,
		TracingEnabled:              enableTracing,
		OtelSidecarEnabled:          enableOtelSidecar,
		OtelCertificateSecret:       openTelemetryCertificateSecret,
		OtelClientCertificateSecret: openTelemetryClientCertificateSecret,
	}
	if err = setupReconcilers(mgr,
		mgrOpts.DeploymentsNamespace,
		config,
		otelConfiguration,
	); err != nil {
		setupLog.Error(err, "unable to create controllers")
		retcode = 1
		return
	}

	if err = setupWebhooks(mgr, mgrOpts.DeploymentsNamespace); err != nil {
		setupLog.Error(err, "unable to create webhooks")
		retcode = 1
		return
	}

	//+kubebuilder:scaffold:builder

	if err = setupProbes(mgr); err != nil {
		setupLog.Error(err, "unable to set up probes")
		retcode = 1
		return
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		retcode = 1
		return
	}
}

func setupManager(mgrOpts ManagerOptions) (ctrl.Manager, error) {
	clientCAName := ""
	if mgrOpts.EnableMutualTLS {
		// The WebhookServer shares the same CertDir for both the server
		// certificate and the client CA certificate. We expect the ClientCACert
		// in the "client-ca"  sub-folder from the ConfigMap, since one cannot
		// mount several Secrets/ConfigMaps under the same path.
		clientCAName = filepath.Join("client-ca", constants.ClientCACert)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: mgrOpts.MetricsAddr,
		},
		HealthProbeBindAddress: mgrOpts.ProbeAddr,
		LeaderElection:         mgrOpts.EnableLeaderElection,
		LeaderElectionID:       "a4ddbf36.kubewarden.io",
		Cache:                  controller.NamespacedCacheOptions(mgrOpts.DeploymentsNamespace),
		WebhookServer: webhook.NewServer(webhook.Options{
			ClientCAName: clientCAName,
		}),
	})
	if err != nil {
		return mgr, fmt.Errorf("failed to setup manager: %w", err)
	}
	return mgr, nil
}

func setupProbes(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return errors.Join(errors.New("unable to set up health check"), err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return errors.Join(errors.New("unable to set up ready check"), err)
	}
	return nil
}

func setupReconcilers(mgr ctrl.Manager,
	deploymentsNamespace string,
	config Configuration,
	otelConfiguration controller.TelemetryConfiguration,
) error {
	if err := (&controller.PolicyServerReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("policy-server-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: config.AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		TelemetryConfiguration:                             otelConfiguration,
		ClientCAConfigMapName:                              config.ClientCAConfigMapName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create PolicyServer controller"), err)
	}

	if err := (&controller.AdmissionPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("admission-policy-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create AdmissionPolicy controller"), err)
	}

	if err := (&controller.ClusterAdmissionPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("cluster-admission-policy-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicy controller"), err)
	}

	if err := (&controller.CertReconciler{
		Client:                      mgr.GetClient(),
		Log:                         ctrl.Log.WithName("cert-recociler"),
		DeploymentsNamespace:        deploymentsNamespace,
		WebhookServiceName:          config.WebhookServiceName,
		CARootSecretName:            constants.CARootSecretName,
		WebhookServerCertSecretName: constants.WebhookServerCertSecretName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create Cert controller"), err)
	}

	if err := (&controller.AdmissionPolicyGroupReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("admission-policy-group-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create AdmissionPolicyGroup controller"), err)
	}

	if err := (&controller.ClusterAdmissionPolicyGroupReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("cluster-admission-policy-group-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicyGroup controller"), err)
	}
	return nil
}

func setupWebhooks(mgr ctrl.Manager, deploymentsNamespace string) error {
	if err := (&policiesv1.PolicyServer{}).SetupWebhookWithManager(mgr, deploymentsNamespace); err != nil {
		return errors.Join(errors.New("unable to create webhook for policy servers"), err)
	}
	if err := (&policiesv1.ClusterAdmissionPolicy{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for cluster admission policies"), err)
	}
	if err := (&policiesv1.AdmissionPolicy{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for admission policies"), err)
	}
	if err := (&policiesv1.AdmissionPolicyGroup{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for admission policies groups"), err)
	}
	if err := (&policiesv1.ClusterAdmissionPolicyGroup{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for cluster admission policies groups"), err)
	}
	return nil
}
