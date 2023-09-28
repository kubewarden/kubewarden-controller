package webhookwrapper

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	controllerCrypto "github.com/kubewarden/kubewarden-controller/internal/pkg/crypto"
)

func NewManager(options ctrl.Options, logger logr.Logger, developmentMode bool, webhookAdvertiseHost string, webhooks WebhookRegistrators) ctrl.Manager {
	var config *restclient.Config
	var clientset *kubernetes.Clientset
	serverOptions := webhook.Options{}
	caCert := []byte("")

	if developmentMode {
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			panic(err.Error())
		}

		// use the current context in kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", path.Join(userHomeDir, ".kube", "config"))
		if err != nil {
			panic(err.Error())
		}

		// create the clientset
		clientset, err = kubernetes.NewForConfig(config)
		if err != nil {
			panic(err.Error())
		}

		// create certificates
		var certDir string
		caCert, certDir, err = createCertificates(logger, []string{webhookAdvertiseHost})
		if err != nil {
			logger.Error(err, "unable to create certificates")
			os.Exit(1)
		}

		serverOptions.CertDir = certDir
		serverOptions.Host = webhookAdvertiseHost
		serverOptions.Port = 9443
		options.WebhookServer = webhook.NewServer(serverOptions)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		logger.Error(err, "unable to start manager")
		os.Exit(1)
	}

	registerWebhooks(logger, mgr, webhookAdvertiseHost, developmentMode, clientset, caCert, webhooks, serverOptions)

	return mgr
}

func createCertificates(logger logr.Logger, subjectAlternativeNames []string) ([]byte, string, error) {
	dir, err := os.MkdirTemp(os.TempDir(), "webhookwrapper-certs-*")
	if err != nil {
		logger.Error(err, "unable to create temporary directory")
		os.Exit(1)
	}
	CA, err := controllerCrypto.GenerateCA()
	if err != nil {
		return []byte{}, "", errors.Join(errors.New("cannot generate root CA"), err)
	}
	certificate, certificateKey, err := controllerCrypto.GenerateCert(CA.CaCertBytes, subjectAlternativeNames, CA.CaPrivateKey)

	if err != nil {
		logger.Error(err, "unable to create certificate")
		os.Exit(1)
	}
	if err := os.WriteFile(path.Join(dir, "tls.key"), certificateKey.Bytes(), 0600); err != nil {
		logger.Error(err, "unable to write certificate key")
		os.Exit(1)
	}
	if err := os.WriteFile(path.Join(dir, "tls.crt"), certificate.Bytes(), 0600); err != nil {
		logger.Error(err, "unable to write certificate")
		os.Exit(1)
	}
	return certificate.Bytes(), dir, nil
}

type WebhookRegistrator struct {
	Registrator         func(ctrl.Manager) error
	Name                string
	RulesWithOperations []admissionregistrationv1.RuleWithOperations
	Mutating            bool
	WebhookPath         string
}
type WebhookRegistrators = []WebhookRegistrator

func registerWebhooks(logger logr.Logger, mgr ctrl.Manager, webhookAdvertiseHost string, developmentMode bool, clientset *kubernetes.Clientset, caCertificate []byte, webhookRegistrators WebhookRegistrators, managerOptions webhook.Options) {
	ctx := context.TODO()
	for _, webhookRegistrator := range webhookRegistrators {
		if err := webhookRegistrator.Registrator(mgr); err != nil {
			logger.Error(err, "unable to create webhook")
		}
		if !developmentMode {
			continue
		}
		failurePolicy := admissionregistrationv1.Fail
		sideEffectsNone := admissionregistrationv1.SideEffectClassNone
		webhookEndpoint := url.URL{
			Scheme: "https",
			Host:   fmt.Sprintf("%s:%d", webhookAdvertiseHost, managerOptions.Port),
			Path:   webhookRegistrator.WebhookPath,
		}
		webhookEndpointString := webhookEndpoint.String()
		if err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, webhookRegistrator.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "unable to cleanup existing webhook")
			os.Exit(1)
		}
		if err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, webhookRegistrator.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "unable to cleanup existing webhook")
			os.Exit(1)
		}
		if webhookRegistrator.Mutating {
			_, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(
				ctx,
				&admissionregistrationv1.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: webhookRegistrator.Name,
					},
					Webhooks: []admissionregistrationv1.MutatingWebhook{
						{
							Name: webhookRegistrator.Name,
							ClientConfig: admissionregistrationv1.WebhookClientConfig{
								URL:      &webhookEndpointString,
								CABundle: caCertificate,
							},
							Rules:                   webhookRegistrator.RulesWithOperations,
							FailurePolicy:           &failurePolicy,
							SideEffects:             &sideEffectsNone,
							AdmissionReviewVersions: []string{"v1"},
						},
					},
				},
				metav1.CreateOptions{},
			)
			if err != nil {
				logger.Error(err, "unable to register webhook")
				os.Exit(1)
			}
		} else {
			_, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(
				ctx,
				&admissionregistrationv1.ValidatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: webhookRegistrator.Name,
					},
					Webhooks: []admissionregistrationv1.ValidatingWebhook{
						{
							Name: webhookRegistrator.Name,
							ClientConfig: admissionregistrationv1.WebhookClientConfig{
								URL:      &webhookEndpointString,
								CABundle: caCertificate,
							},
							Rules:                   webhookRegistrator.RulesWithOperations,
							FailurePolicy:           &failurePolicy,
							SideEffects:             &sideEffectsNone,
							AdmissionReviewVersions: []string{"v1"},
						},
					},
				},
				metav1.CreateOptions{},
			)
			if err != nil {
				logger.Error(err, "unable to register webhook")
				os.Exit(1)
			}
		}
	}
}
