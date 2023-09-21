package policyserver

import (
	"context"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateImagePullSecret(t *testing.T) {
	ctx := context.Background()
	deploymentsNamespace := "test"

	tests := []struct {
		name            string
		imagePullSecret string
		secret          *v1.Secret
		valid           bool
	}{
		{
			"non existing secret",
			"test",
			nil,
			false,
		},
		{
			"secret of wrong type",
			"test",
			&v1.Secret{
				Type: "Opaque",
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			},
			false,
		},
		{
			"valid secret",
			"test",
			&v1.Secret{
				Type: "kubernetes.io/dockerconfigjson",
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().Build()

			if test.secret != nil {
				err := k8sClient.Create(ctx, test.secret)
				if err != nil {
					t.Errorf("failed to create secret: %s", err.Error())
				}
			}

			err := ValidateImagePullSecret(ctx, k8sClient, test.imagePullSecret, deploymentsNamespace)
			if err != nil && test.valid {
				t.Errorf("unexpected error: %s", err.Error())
			} else if err == nil && !test.valid {
				t.Errorf("expected error, got nil")
			}
		})
	}
}
