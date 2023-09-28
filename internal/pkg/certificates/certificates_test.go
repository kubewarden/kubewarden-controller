package certificates

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const deploymentsNamespace = "namespace"

func TestCACreation(t *testing.T) {
	k8sClient := fake.NewClientBuilder().Build()
	_, err := createRootCa(context.TODO(), k8sClient, deploymentsNamespace)
	if err != nil {
		t.Fatalf("unexpected error: %q", err)
	}
	if err := k8sClient.Get(context.TODO(), client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.RootCASecretName}, &corev1.Secret{}); err != nil {
		if apierrors.IsNotFound(err) {
			t.Fatal("root ca secret not found")
		}
		t.Fatalf("unexpected error while fetching root ca secret: %q", err)
	}
}

func TestRenewControllerCerts(t *testing.T) {
	k8sClient := fake.NewClientBuilder().Build()
	rootCA, err := createRootCa(context.TODO(), k8sClient, deploymentsNamespace)
	if err != nil {
		t.Fatalf("unexpected error: %q", err)
	}
	if err := renewControllerCerts(context.TODO(), k8sClient, rootCA, []string{"localhost"}, deploymentsNamespace); err != nil {
		t.Fatalf("unexpected error: %q", err)
	}
	if err := k8sClient.Get(context.TODO(), client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.ControllerCertsSecretName}, &corev1.Secret{}); err != nil {
		if apierrors.IsNotFound(err) {
			t.Fatal("root ca secret not found")
		}
		t.Fatalf("unexpected error while fetching root ca secret: %q", err)
	}
}

func TestUpdateWebhooksCaBundle(t *testing.T) {
	k8sClient := fake.NewClientBuilder().WithObjects(
		&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ControllerValidatingWebhookName,
				Namespace: deploymentsNamespace,
			},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
			}},
		},
		&admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ControllerMutatingWebhookName,
				Namespace: deploymentsNamespace,
			},
			Webhooks: []admissionregistrationv1.MutatingWebhook{{
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte(""),
				},
			}},
		},
	).Build()
	caBundle := []byte("fakecabundle")
	if err := updateWebhooksCaBundle(context.TODO(), k8sClient, deploymentsNamespace, caBundle); err != nil {
		t.Fatalf("unexpected error: %q", err)
	}
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: constants.ControllerValidatingWebhookName, Namespace: deploymentsNamespace}, webhookConfig); err != nil {
		t.Fatalf("cannot get controller validation webhook: %q", err)
	}
	for i := range webhookConfig.Webhooks {
		if diff := cmp.Diff(webhookConfig.Webhooks[i].ClientConfig.CABundle, caBundle); diff != "" {
			t.Errorf("invalid caBundle: %s", diff)
		}
	}
	mutatingWebhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: constants.ControllerMutatingWebhookName, Namespace: deploymentsNamespace}, mutatingWebhookConfig); err != nil {
		t.Fatalf("cannot list Kubewarden mutating webhooks: %q", err)
	}
	for i := range mutatingWebhookConfig.Webhooks {
		if diff := cmp.Diff(mutatingWebhookConfig.Webhooks[i].ClientConfig.CABundle, caBundle); diff != "" {
			t.Errorf("invalid caBundle: %s", diff)
		}
	}
}

func TestWaitForFiles(t *testing.T) {
	t.Run("wait for file that already exist", func(t *testing.T) {
		tempCertificateDirectory, err := os.MkdirTemp(t.TempDir(), "")
		if err != nil {
			t.Fatalf("cannot create certificate directory: %q", err)
		}
		crt := filepath.Join(tempCertificateDirectory, corev1.TLSCertKey)
		if err := os.WriteFile(crt, []byte("content"), 0400); err != nil {
			t.Fatal(err)
		}

		key := filepath.Join(tempCertificateDirectory, corev1.TLSPrivateKeyKey)
		if err := os.WriteFile(key, []byte("content"), 0400); err != nil {
			t.Fatal(err)
		}
		if err := waitForCertificatesFiles(tempCertificateDirectory, 30*time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wait for file that is missing", func(t *testing.T) {
		tempCertificateDirectory, err := os.MkdirTemp(t.TempDir(), "")
		if err != nil {
			t.Fatalf("cannot create certificate directory: %q", err)
		}
		go func() {
			time.Sleep(10 * time.Second)
			crt := filepath.Join(tempCertificateDirectory, corev1.TLSCertKey)
			if err := os.WriteFile(crt, []byte("content"), 0400); err != nil {
				t.Errorf("fail to create file %s: %q", crt, err)
			}

			key := filepath.Join(tempCertificateDirectory, corev1.TLSPrivateKeyKey)
			if err := os.WriteFile(key, []byte("content"), 0400); err != nil {
				t.Errorf("fail to create file %s: %q", crt, err)
			}
		}()
		if err := waitForCertificatesFiles(tempCertificateDirectory, 30*time.Second); err != nil {
			t.Fatal(err)
		}
	})
}
