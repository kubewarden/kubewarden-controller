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
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/ereslibre/kube-webhook-wrapper/webhookwrapper"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policiesv1 "github.com/kubewarden/kubewarden-controller/apis/policies/v1"
	v1alpha2 "github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	controllers "github.com/kubewarden/kubewarden-controller/controllers"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/metrics"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
	utilruntime.Must(policiesv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var deploymentsNamespace string
	var alwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool
	var probeAddr string
	var enableMetrics bool
	var openTelemetryEndpoint string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8088", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableMetrics, "enable-metrics", false,
		"Enable metrics collection about policy server and cluster admission policies")
	flag.StringVar(&openTelemetryEndpoint, "opentelemetry-endpoint", "127.0.0.1:4317", "The OpenTelemetry connection endpoint")
	flag.StringVar(&constants.DefaultPolicyServer, "default-policy-server", "", "The default policy server to set on policies before they are persisted")
	opts := zap.Options{
		Development: true,
	}
	flag.StringVar(&deploymentsNamespace,
		"deployments-namespace",
		"",
		"The namespace where the kubewarden resources will be created.")
	flag.BoolVar(&alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		"always-accept-admission-reviews-on-deployments-namespace",
		false,
		"Always accept admission reviews targeting the deployments-namespace.")
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	environment := readEnvironment()

	if deploymentsNamespace == "" {
		deploymentsNamespace = environment.deploymentsNamespace
	}

	if enableMetrics {
		if err := metrics.New(openTelemetryEndpoint); err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			os.Exit(1)
		}
		setupLog.Info("Metrics initialized")
	}

	mgr, err := webhookwrapper.NewManager(
		ctrl.Options{
			Scheme:                 scheme,
			MetricsBindAddress:     metricsAddr,
			Host:                   environment.webhookHostListen,
			Port:                   9443,
			HealthProbeBindAddress: probeAddr,
			LeaderElection:         enableLeaderElection,
			LeaderElectionID:       "a4ddbf36.kubewarden.io",
			ClientDisableCacheFor:  []client.Object{&corev1.ConfigMap{}, &appsv1.Deployment{}},
		},
		setupLog,
		environment.developmentMode,
		environment.webhookHostAdvertise,
		webhooks(),
	)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	reconciler := admission.Reconciler{
		Client:               mgr.GetClient(),
		APIReader:            mgr.GetAPIReader(),
		Log:                  ctrl.Log.WithName("reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
	}

	if err = (&controllers.PolicyServerReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("policy-server-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PolicyServer")
		os.Exit(1)
	}

	if err = (&controllers.AdmissionPolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("admission-policy-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AdmissionPolicy")
		os.Exit(1)
	}

	if err = (&controllers.ClusterAdmissionPolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("cluster-admission-policy-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterAdmissionPolicy")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func webhooks() []webhookwrapper.WebhookRegistrator {
	return []webhookwrapper.WebhookRegistrator{
		{
			Registrator: (&v1alpha2.PolicyServer{}).SetupWebhookWithManager,
			Name:        "mutate-policyservers.kubewarden.dev",
			RulesWithOperations: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{v1alpha2.GroupVersion.Group},
						APIVersions: []string{v1alpha2.GroupVersion.Version},
						Resources:   []string{"policyservers"},
					},
				},
			},
			WebhookPath: "/mutate-policies-kubewarden-io-v1alpha2-policyserver",
			Mutating:    true,
		},
		{
			Registrator: (&policiesv1.ClusterAdmissionPolicy{}).SetupWebhookWithManager,
			Name:        "mutate-clusteradmissionpolicies.kubewarden.dev",
			RulesWithOperations: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{policiesv1.GroupVersion.Group},
						APIVersions: []string{policiesv1.GroupVersion.Version},
						Resources:   []string{"clusteradmissionpolicies"},
					},
				},
			},
			WebhookPath: "/mutate-policies-kubewarden-io-v1-clusteradmissionpolicy",
			Mutating:    true,
		},
		{
			Registrator: (&policiesv1.ClusterAdmissionPolicy{}).SetupWebhookWithManager,
			Name:        "validate-clusteradmissionpolicies.kubewarden.dev",
			RulesWithOperations: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{policiesv1.GroupVersion.Group},
						APIVersions: []string{policiesv1.GroupVersion.Version},
						Resources:   []string{"clusteradmissionpolicies"},
					},
				},
			},
			WebhookPath: "/validate-policies-kubewarden-io-v1-clusteradmissionpolicy",
			Mutating:    false,
		},
		{
			Registrator: (&policiesv1.AdmissionPolicy{}).SetupWebhookWithManager,
			Name:        "mutate-admissionpolicies.kubewarden.dev",
			RulesWithOperations: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{policiesv1.GroupVersion.Group},
						APIVersions: []string{policiesv1.GroupVersion.Version},
						Resources:   []string{"admissionpolicies"},
					},
				},
			},
			WebhookPath: "/mutate-policies-kubewarden-io-v1-admissionpolicy",
			Mutating:    true,
		},
		{
			Registrator: (&policiesv1.AdmissionPolicy{}).SetupWebhookWithManager,
			Name:        "validate-admissionpolicies.kubewarden.dev",
			RulesWithOperations: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{policiesv1.GroupVersion.Group},
						APIVersions: []string{policiesv1.GroupVersion.Version},
						Resources:   []string{"admissionpolicies"},
					},
				},
			},
			WebhookPath: "/validate-policies-kubewarden-io-v1-admissionpolicy",
			Mutating:    false,
		},
	}
}
