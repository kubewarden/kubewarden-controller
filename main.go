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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/kubewarden/kube-webhook-wrapper/webhookwrapper"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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

	// "sigs.k8s.io/controller-runtime/pkg/manager"

	controllers "github.com/kubewarden/kubewarden-controller/controllers"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
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

func main() { //nolint:cyclop
	retcode := constants.ControllerReturnCodeSuccess
	defer func() { os.Exit(retcode) }()

	var metricsAddr string
	var enableLeaderElection bool
	var deploymentsNamespace string
	var alwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool
	var probeAddr string
	var enableMetrics bool
	var openTelemetryEndpoint string
	var validatingWebhooks string
	var mutatingWebhooks string
	var controllerWebhookService string
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
	flag.StringVar(&validatingWebhooks,
		"validating-webhooks",
		"kubewarden-controller-validating-webhook-configuration",
		"Comma separated ValidatingWebhookConfiguration names which should be updated adding the root CA bundle")
	flag.StringVar(&mutatingWebhooks,
		"mutating-webhooks",
		"kubewarden-controller-mutating-webhook-configuration",
		"Comma separated MutatingWebhookConfiguration names which should be updated adding the root CA bundle")
	flag.StringVar(&controllerWebhookService,
		"controller-webhook-service",
		"kubewarden-controller-webhook-service",
		"Controller service name used for controller webhooks")
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

	managerCtx := ctrl.SetupSignalHandler()
	rootCACertPem, rootCAPrivateKey, shouldRestart, err := setupClusterClientAndSetupCA(managerCtx, controllerWebhookService, deploymentsNamespace, validatingWebhooks, mutatingWebhooks, environment.developmentMode)
	if err != nil {
		retcode = constants.ControllerReturnCodeError
		return
	} else if shouldRestart {
		// When the controller is run for the first time, there
		// is no root CA. Therefore, we need to restart the pod
		// to ensure that secret data is available for the
		// controller before start running the manager. Here we
		// just exit the controller. Thus, the control plane
		// will launch another container with access to the
		// root CA data initialized in the first run.
		setupLog.Info("Root CA or controller certificate initialized. Restarting. ")
		retcode = constants.ControllerReturnCodeCAInitialized
		return
	}

	if enableMetrics {
		shutdown, err := metrics.New(openTelemetryEndpoint)
		if err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			retcode = constants.ControllerReturnCodeError
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
				retcode = constants.ControllerReturnCodeError
				return
			}
		}()
	}

	namespaceSelector := cache.ObjectSelector{
		Field: fields.ParseSelectorOrDie(fmt.Sprintf("metadata.namespace=%s", deploymentsNamespace)),
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
			NewCache: cache.BuilderWithOptions(cache.Options{
				SelectorsByObject: map[client.Object]cache.ObjectSelector{
					&appsv1.ReplicaSet{}: namespaceSelector,
					&corev1.Secret{}:     namespaceSelector,
					&corev1.Pod{}:        namespaceSelector,
					&corev1.Service{}:    namespaceSelector,
				},
			}),
			// These types of resources should never be cached because we need fresh
			// data coming from the client. This is required to perform the rollout
			// of the PolicyServer Deployment whenever a policy is added/changed/removed.
			// Because of that, there's not need to scope these resources inside
			// of the cache, like we did for Pods, Services,... right above.
			ClientDisableCacheFor: []client.Object{&corev1.ConfigMap{}, &appsv1.Deployment{}},
		},
		setupLog,
		environment.developmentMode,
		environment.webhookHostAdvertise,
		webhooks(),
		rootCACertPem,
		rootCAPrivateKey,
	)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		retcode = constants.ControllerReturnCodeError
		return
	}

	reconciler := admission.Reconciler{
		Client:               mgr.GetClient(),
		APIReader:            mgr.GetAPIReader(),
		Log:                  ctrl.Log.WithName("reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: alwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		MetricsEnabled: enableMetrics,
	}

	if err = (&controllers.PolicyServerReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("policy-server-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PolicyServer")
		retcode = constants.ControllerReturnCodeError
		return
	}

	if err = (&controllers.AdmissionPolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("admission-policy-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AdmissionPolicy")
		retcode = constants.ControllerReturnCodeError
		return
	}

	if err = (&controllers.ClusterAdmissionPolicyReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Log:        ctrl.Log.WithName("cluster-admission-policy-reconciler"),
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterAdmissionPolicy")
		retcode = constants.ControllerReturnCodeError
		return
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		retcode = constants.ControllerReturnCodeError
		return
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(managerCtx); err != nil {
		setupLog.Error(err, "problem running manager")
		retcode = constants.ControllerReturnCodeError
		return
	}
}

func webhooks() []webhookwrapper.WebhookRegistrator {
	return []webhookwrapper.WebhookRegistrator{
		{
			Registrator: (&policiesv1.PolicyServer{}).SetupWebhookWithManager,
			Name:        "mutate-policyservers.kubewarden.dev",
			RulesWithOperations: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{policiesv1.GroupVersion.Group},
						APIVersions: []string{policiesv1.GroupVersion.Version},
						Resources:   []string{"policyservers"},
					},
				},
			},
			WebhookPath: "/mutate-policies-kubewarden-io-v1-policyserver",
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

func setupClusterClientAndSetupCA(ctx context.Context, controllerWebhookService string, deploymentsNamespace string, validatingWebhooks string, mutatingWebhooks string, developmentMode bool) ([]byte, []byte, bool, error) {
	// This client is not created inside the setupCA function just to
	// facilitate the testing
	clusterClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{})
	if err != nil {
		setupLog.Error(err, "unable to setup client")
		return []byte{}, []byte{}, false, fmt.Errorf("failed to initialize the cluster client: %s", err.Error())
	}
	return setupCA(ctx, clusterClient, controllerWebhookService, deploymentsNamespace, strings.Split(strings.TrimSpace(validatingWebhooks), ","), strings.Split(strings.TrimSpace(mutatingWebhooks), ","), developmentMode)
}

// setupCA is a function used to initialize the root CA, the certificate used
// by the controller to serve the webhook server.
//
// ctx is the context used with the clusterClient to get and patch cluster
// information  resources.
//
// controllerWebhookService is the service name used to access the webhook server
// available by the controller. This is necessary to properly generate the
// certificate
//
// deploymentsNamespace is the namespace where the controller is deployed
//
// validatingWebhooks are the ValidatingWebhookConfiguration names which should
// be updated when the root CA is initialized
//
// mutatingWebhooks are the MutatingWebhookConfiguration names which should
// be updated when the root CA is initialized
//
// developmentMode is a flag to tell if the controller is running on
// development mode or not
func setupCA(ctx context.Context, clusterClient client.Client, controllerWebhookService string, deploymentsNamespace string, validatingWebhooks []string, mutatingWebhooks []string, developmentMode bool) ([]byte, []byte, bool, error) {
	caSecret, caInitialized, err := admission.FetchOrInitializeCARootSecret(ctx, clusterClient, deploymentsNamespace, admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
	if err != nil {
		return []byte{}, []byte{}, false, fmt.Errorf("failed to fetch or initialize root CA certificate secret: %s", err.Error())
	}
	if caInitialized {
		if err = admission.ReconcileSecret(ctx, clusterClient, caSecret); err != nil {
			return []byte{}, []byte{}, false, fmt.Errorf("failed to reconcile root CA certificate secret: %s", err.Error())
		}
	}

	certificate, privateKey, err := admission.ExtractCertificateData(caSecret)
	if err != nil {
		return []byte{}, []byte{}, false, fmt.Errorf("failed to initialize root CA certificate")
	}

	controllerSecret, initialized, err := admission.FetchOrInitializeCertificate(ctx, clusterClient, controllerWebhookService, deploymentsNamespace, constants.ControllerCertificateSecretName, caSecret, admissionregistration.GenerateCert)
	if err != nil {
		return []byte{}, []byte{}, false, fmt.Errorf("failed to fetch or init the controller certificate: %s ", err.Error())
	}
	if initialized {
		if err = admission.ReconcileSecret(ctx, clusterClient, controllerSecret); err != nil {
			return []byte{}, []byte{}, false, fmt.Errorf("cannot reconcile secret %s: %s", controllerSecret.Name, err.Error())
		}
	}

	if !developmentMode {
		if err := setupCAWebhooksInDevelopmentMode(ctx, clusterClient, certificate, validatingWebhooks, mutatingWebhooks); err != nil {
			return []byte{}, []byte{}, false, fmt.Errorf("failed to configure webhooks in development mode: %s", err.Error())
		}
	}
	return certificate, privateKey, (caInitialized || initialized), nil
}

func setupCAWebhooksInDevelopmentMode(ctx context.Context, clusterClient client.Client, certificate []byte, validatingWebhooks []string, mutatingWebhooks []string) error {
	// If the controller is NOT running in development mode, the
	// webhooks are created by Helm chart and missing the
	// `caBundle` field with the root CA certificate. Therefore,
	// the controller needs to patch these resources
	if err := configureControllerValidationWebhooksToUseRootCA(ctx, clusterClient, certificate, validatingWebhooks); err != nil {
		return err
	}
	return configureControllerMutatingWebhooksToUseRootCA(ctx, clusterClient, certificate, mutatingWebhooks)
}

// configureControllerMutatingWebhooksToUseRootCA sets the `caBundle` field for
// the admissionregistrationv1.MutatingWebhookConfiguration webhook targeting
// the controller filling up the field with the root CA certificate.
//
// ctx is the context used with the clusterClient to get and patch cluster
// information  resources.
//
// caCertificate is the root CA certificate to be added in the `caBundle`
// field.
//
// mutatingWebhookNames is the MutatingWebhookConfiguration names where the
// webhook should be patched with the root CA certificate
func configureControllerMutatingWebhooksToUseRootCA(ctx context.Context, clusterClient client.Client, caCertificate []byte, mutatingWebhookNames []string) error {
	for _, mutatingWebhookName := range mutatingWebhookNames {
		webhookConfig := admissionregistrationv1.MutatingWebhookConfiguration{}
		if err := clusterClient.Get(ctx, client.ObjectKey{Name: mutatingWebhookName}, &webhookConfig); err != nil {
			return fmt.Errorf("cannot get MutatingWebhookConfiguration %s: %s", mutatingWebhookName, err.Error())
		}
		patch := webhookConfig.DeepCopy()
		for i := range patch.Webhooks {
			patch.Webhooks[i].ClientConfig.CABundle = caCertificate
		}
		if err := clusterClient.Patch(ctx, patch, client.MergeFrom(&webhookConfig)); err != nil {
			return fmt.Errorf("cannot patch MutatingWebhookConfiguration %s: %s", mutatingWebhookName, err.Error())
		}
	}
	return nil
}

// configureControllerValidationWebhooksToUseRootCA sets the `caBundle` field for
// the admissionregistrationv1.ValidatingWebhookConfiguration webhook targeting
// the controller filling up the field with the root CA certificate.
//
// ctx is the context used with the clusterClient to get and patch cluster
// information  resources.
//
// caCertificate is the root CA certificate to be added in the `caBundle`
// field.
//
// validatingWebhookNames is the ValidatingWebhookConfiguration names where the
// webhook should be patched with the root CA certificate
func configureControllerValidationWebhooksToUseRootCA(ctx context.Context, clusterClient client.Client, caCertificate []byte, validatingWebhookNames []string) error {
	for _, validatingWebhookName := range validatingWebhookNames {
		webhookConfig := admissionregistrationv1.ValidatingWebhookConfiguration{}
		if err := clusterClient.Get(ctx, client.ObjectKey{Name: validatingWebhookName}, &webhookConfig); err != nil {
			return fmt.Errorf("cannot get ValidatingWebhookConfiguration %s: %s", validatingWebhookName, err.Error())
		}
		patch := webhookConfig.DeepCopy()
		for i := range patch.Webhooks {
			patch.Webhooks[i].ClientConfig.CABundle = caCertificate
		}
		if err := clusterClient.Patch(ctx, patch, client.MergeFrom(&webhookConfig)); err != nil {
			return fmt.Errorf("cannot patch ValidatingWebhookConfiguration %s: %s", validatingWebhookName, err.Error())
		}
	}
	return nil
}
