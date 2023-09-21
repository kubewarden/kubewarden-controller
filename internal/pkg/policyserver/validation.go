package policyserver

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ValidateImagePullSecret validates that the specified PolicyServer imagePullSecret exists and is of type kubernetes.io/dockerconfigjson
func ValidateImagePullSecret(ctx context.Context, k8sClient client.Client, imagePullSecret string, deploymentsNamespace string) error {
	// By using Unstructured data we force the client to fetch fresh, uncached
	// data from the API server
	unstructuredObj := &unstructured.Unstructured{}
	unstructuredObj.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "Secret",
		Version: "v1",
	})
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: deploymentsNamespace,
		Name:      imagePullSecret,
	}, unstructuredObj)
	if err != nil {
		return fmt.Errorf("cannot get spec.ImagePullSecret: %w", err)
	}

	var secret corev1.Secret
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(unstructuredObj.UnstructuredContent(), &secret)
	if err != nil {
		return fmt.Errorf("spec.ImagePullSecret is not of Kind Secret: %w", err)
	}

	if secret.Type != "kubernetes.io/dockerconfigjson" {
		return fmt.Errorf("spec.ImagePullSecret secret \"%s\" is not of type kubernetes.io/dockerconfigjson", secret.Name)
	}

	return nil
}
