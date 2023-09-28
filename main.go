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
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	controllers "github.com/kubewarden/kubewarden-controller/controllers"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/certificates"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/metrics"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1alpha2"
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
	retcode := 0
	defer func() { os.Exit(retcode) }()

	var metricsAddr string
	var enableLeaderElection bool
	var deploymentsNamespace string
	var alwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool
	var probeAddr string
	var enableMetrics bool
	var enableTracing bool
	var openTelemetryEndpoint string
	var controllerWebhookServiceName string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8088", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableMetrics, "enable-metrics", false,
		"Enable metrics collection for all Policy Servers and the Kubewarden Controller")
	flag.BoolVar(&enableTracing, "enable-tracing", false,
		"Enable tracing collection for all Policy Servers")
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
	// the following cli flag is required because the service name is defined
	// in the helm chart templates.
	flag.StringVar(&controllerWebhookServiceName,
		"webhook-server-service",
		"kubewarden-controller-webhook-service",
		"The service name of the controller webhook server service")
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	controllerContext := ctrl.SetupSignalHandler()
	if err := setupCA(controllerContext, deploymentsNamespace, controllerWebhookServiceName); err != nil {
		setupLog.Error(err, "failed to setup required certificates")
		retcode = 1
		return
	}

	if enableMetrics {
		shutdown, err := metrics.New(openTelemetryEndpoint)
		if err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			retcode = 1
			return
		}
		setupLog.Info("Metrics initialized")

		// cleanly shutdown and flush telemetry on application exit
		defer func() {
			// Do not make the application hang when it is shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			if err := shutdown(ctx); err != nil {
				setupLog.Error(err, "Unable to shutdown telemetry")
				retcode = 1
				return
			}
		}()
	}

	namespaceSelector := cache.ByObject{
		Field: fields.ParseSelectorOrDie(fmt.Sprintf("metadata.namespace=%s", deploymentsNamespace)),
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "a4ddbf36.kubewarden.io",
		// Warning: the manager creates a client, which then uses Watches to monitor
		// certain resources. By default, the client is not going to be namespaced,
		// it will be able to watch resources across the entire cluster. This is of
		// course constrained by the RBAC rules applied to the ServiceAccount that
		// runs the controller.
		// **However**, even when accessing a resource inside of a specific Namespace,
		// the default behaviour of the cache is to create a Watch that is not namespaced;
		// hence requires the privilege to access all the resources of that type inside
		// of the cluster. That can cause runtime error if the ServiceAccount lacking
		// this privilege.
		// For example, when we access a secret inside the `kubewarden`
		// namespace, the cache will create a Watch against Secrets, that will require
		// privileged to access ALL the secrets of the cluster.
		//
		// To be able to have stricter RBAC rules, we need to instruct the cache to
		// only watch objects inside of the namespace where the controller is running.
		// That applies ONLY to the namespaced resources that we know the controller
		// is going to own inside of a specific namespace.
		// For example, Secret resources are going to be defined by the controller
		// only inside of the `kubewarden` namespace; hence their watch can be namespaced.
		// On the other hand, AdmissionPolicy resources are namespaced, but the controller
		// requires to access them across all the namespaces of the cluster; hence the
		// cache must not be namespaced.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&appsv1.ReplicaSet{}: namespaceSelector,
				&corev1.Secret{}:     namespaceSelector,
				&corev1.Pod{}:        namespaceSelector,
				&corev1.Service{}:    namespaceSelector,
			},
		},
		// These types of resources should never be cached because we need fresh
		// data coming from the client. This is required to perform the rollout
		// of the PolicyServer Deployment whenever a policy is added/changed/removed.
		// Because of that, there's not need to scope these resources inside
		// of the cache, like we did for Pods, Services,... right above.
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{&corev1.ConfigMap{}, &appsv1.Deployment{}},
			},
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		retcode = 1
		return
	}

	if err := setupReconcilers(mgr, deploymentsNamespace, enableMetrics, enableTracing, alwaysAcceptAdmissionReviewsOnDeploymentsNamespace); err != nil {
		retcode = 1
		return
	}

	if err := setupWebhooks(mgr, deploymentsNamespace); err != nil {
		retcode = 1
		return
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		retcode = 1
		return
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(controllerContext); err != nil {
		setupLog.Error(err, "problem running manager")
		retcode = 1
		return
	}
}

func setupReconcilers(mgr ctrl.Manager, deploymentsNamespace string, enableMetrics, enableTracing, alwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool) error {
	reconciler := admission.Reconciler{
		Client:               mgr.GetClient(),
		APIReader:            mgr.GetAPIReader(),
		Log:                  ctrl.Log.WithName("reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		MetricsEnabled: enableMetrics,
		TracingEnabled: enableTracing,
	}

	if err := (&controllers.PolicyServerReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("policy-server-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PolicyServer")
		return errors.Join(errors.New("unable to create PolicyServer controller"), err)
	}

	if err := (&controllers.AdmissionPolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("admission-policy-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AdmissionPolicy")
		return errors.Join(errors.New("unable to create AdmissionPolicy policy server controller"), err)
	}

	if err := (&controllers.ClusterAdmissionPolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("cluster-admission-policy-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterAdmissionPolicy")
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicy policy server controller"), err)
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
	return nil
}

func setupCA(ctx context.Context, deploymentsNamespace string, controllerWebhookServiceName string) error {
	k8sClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{})
	if err != nil {
		return errors.Join(fmt.Errorf("cannot create kubernetes client"), err)
	}
	if err := certificates.SetupCA(ctx, k8sClient, deploymentsNamespace, controllerWebhookServiceName); err != nil {
		return errors.Join(fmt.Errorf("failed to setup CA"), err)
	}
	return nil
}
