package e2e

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const (
	testTimeout      = 5 * time.Minute
	testPollInterval = 1 * time.Second
)

type contextKey string

const (
	policyServerNameKey contextKey = "policyServerName"
	policyNameKey       contextKey = "policyName"
	policyKey           contextKey = "policy"
)

func createNamespaceWithRetry(ctx context.Context, cfg *envconf.Config, name string) error {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	err := cfg.Client().Resources().Create(ctx, namespace)
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func createPolicyServerAndWaitForItsService(ctx context.Context, cfg *envconf.Config, policyServer *policiesv1.PolicyServer) error {
	err := cfg.Client().Resources().Create(ctx, policyServer)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	// Wait for the Service associated with the PolicyServer to be created
	serviceName := policyServer.NameWithPrefix()
	if err := wait.For(func(context.Context) (bool, error) {
		service := &corev1.Service{}
		err := cfg.Client().Resources(namespace).Get(ctx, serviceName, namespace, service)
		if err != nil {
			return false, err
		}
		return true, nil
	}, wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval)); err != nil {
		return err
	}

	// Wait for the Deployment to be available
	return wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: namespace}},
		appsv1.DeploymentAvailable,
		corev1.ConditionTrue,
	), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
}

func getTestCASecret(ctx context.Context, cfg *envconf.Config) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := cfg.Client().Resources(namespace).Get(ctx, constants.CARootSecretName, namespace, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func verifyWebhookMetadata(labels, annotations map[string]string, policyName, policyNamespace string) bool {
	if labels[constants.PartOfLabelKey] != constants.PartOfLabelValue {
		return false
	}
	if annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != policyName {
		return false
	}
	if annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != policyNamespace {
		return false
	}
	return true
}
