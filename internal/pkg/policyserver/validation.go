package policyserver

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ValidateImagePullSecret validates that the specified PolicyServer imagePullSecret exists and is of type kubernetes.io/dockerconfigjson
func ValidateImagePullSecret(ctx context.Context, k8sClient client.Client, imagePullSecret string, deploymentsNamespace string) error {
	secret := &corev1.Secret{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: deploymentsNamespace,
		Name:      imagePullSecret,
	}, secret)
	if err != nil {
		return fmt.Errorf("cannot get spec.ImagePullSecret: %w", err)
	}

	if secret.Type != "kubernetes.io/dockerconfigjson" {
		return fmt.Errorf("spec.ImagePullSecret secret \"%s\" is not of type kubernetes.io/dockerconfigjson", secret.Name)
	}

	return nil
}
