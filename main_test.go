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
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var admissionregCA *admissionregistration.CA
var otherCABundle []byte
var validatingWebhook *admissionregistrationv1.ValidatingWebhookConfiguration
var mutatingWebhook *admissionregistrationv1.MutatingWebhookConfiguration
var otherValidatingWebhook *admissionregistrationv1.ValidatingWebhookConfiguration
var otherMutatingWebhook *admissionregistrationv1.MutatingWebhookConfiguration
var caSecret *corev1.Secret
var controllerSecret *corev1.Secret
var namespace string

func setUPTest(t *testing.T) {
	t.Helper()
	CA, err := admissionregistration.GenerateCA()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	admissionregCA = CA
	namespace = "testingns"
	otherCABundle = []byte("otherCABundle")
	validatingWebhook = &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "validatingWebhookConfig",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "validatingWebhook",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: otherCABundle,
				},
			},
		},
	}
	mutatingWebhook = &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mutatingWebhookConfig",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "mutatingWebhook",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: otherCABundle,
				},
			},
		},
	}
	otherValidatingWebhook = &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "otherValidatingWebhookConfig",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "validatingWebhook",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: otherCABundle,
				},
			},
		},
	}
	otherMutatingWebhook = &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "otherMutatingWebhookConfig",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "mutatingWebhook",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: otherCABundle,
				},
			},
		},
	}
	caSecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.KubewardenCARootSecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			constants.CARootCACert:             admissionregCA.CaCert,
			constants.CARootCACertPem:          admissionregCA.CaCert,
			constants.CARootPrivateKeyCertName: x509.MarshalPKCS1PrivateKey(admissionregCA.CaPrivateKey),
		},
	}
	controllerSecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ControllerCertificateSecretName,
			Namespace: namespace,
		},
		StringData: map[string]string{
			constants.PolicyServerTLSCert: "cert",
			constants.PolicyServerTLSKey:  "key",
		},
		Data: map[string][]byte{
			constants.PolicyServerTLSCert: []byte("cert"),
			constants.PolicyServerTLSKey:  []byte("key"),
		},
	}
}

func TestSetupCA(t *testing.T) { //nolint:cyclop
	setUPTest(t)

	var tests = []struct {
		name                         string
		client                       client.Client
		expectedRootCA               *corev1.Secret
		expectedControllerCert       *corev1.Secret
		validatingWebhookNames       []string
		mutatingWebhookNames         []string
		expectedWebhooksCABundle     map[string][]byte
		shouldInitializeCertificates bool
	}{
		{"fresh installation",
			fake.NewClientBuilder().
				WithObjects(validatingWebhook, mutatingWebhook, otherValidatingWebhook, otherMutatingWebhook).Build(),
			nil, nil,
			[]string{validatingWebhook.Name},
			[]string{mutatingWebhook.Name},
			map[string][]byte{validatingWebhook.Name: []byte(""), mutatingWebhook.Name: []byte(""), "otherValidatingWebhookConfig": otherCABundle, "otherMutatingWebhookConfig": otherCABundle},
			true,
		},
		{"missing controller cert",
			fake.NewClientBuilder().
				WithObjects(caSecret, validatingWebhook, mutatingWebhook, otherValidatingWebhook, otherMutatingWebhook).Build(),
			caSecret, nil,
			[]string{validatingWebhook.Name},
			[]string{mutatingWebhook.Name},
			map[string][]byte{validatingWebhook.Name: []byte(""), mutatingWebhook.Name: []byte(""), "otherValidatingWebhookConfig": otherCABundle, "otherMutatingWebhookConfig": otherCABundle},
			true,
		},
		{"all certs set",
			fake.NewClientBuilder().
				WithObjects(caSecret, controllerSecret, validatingWebhook, mutatingWebhook, otherValidatingWebhook, otherMutatingWebhook).Build(),
			caSecret, controllerSecret,
			[]string{validatingWebhook.Name},
			[]string{mutatingWebhook.Name},
			map[string][]byte{validatingWebhook.Name: []byte(""), mutatingWebhook.Name: []byte(""), "otherValidatingWebhookConfig": otherCABundle, "otherMutatingWebhookConfig": otherCABundle},
			false,
		},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			rootCACertPem, rootCAPrivateKey, initialized, err := setupCA(context.TODO(), ttest.client, "controllerWebhookServerName", namespace, ttest.validatingWebhookNames, ttest.mutatingWebhookNames, false)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if ttest.expectedRootCA != nil {
				if caCertPem, ok := ttest.expectedRootCA.Data[constants.CARootCACertPem]; ok {
					if !bytes.Equal(caCertPem, rootCACertPem) {
						diff := cmp.Diff(caCertPem, rootCACertPem)
						t.Fatalf("invalid root CA cert returned: %s", diff)
					}
				}
				if caPrivateKeyPem, ok := ttest.expectedRootCA.Data[constants.CARootPrivateKeyCertName]; ok {
					if !bytes.Equal(caPrivateKeyPem, rootCAPrivateKey) {
						diff := cmp.Diff(caPrivateKeyPem, rootCAPrivateKey)
						t.Fatalf("invalid root CA private key returned: %s", diff)
					}
				}
			}
			secret := corev1.Secret{}
			if err := ttest.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: constants.KubewardenCARootSecretName}, &secret); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if ttest.expectedRootCA == nil && len(secret.Data) != 3 {
				t.Errorf("invalid secret data: %s", secret.Data)
			}
			if ttest.expectedRootCA != nil && !cmp.Equal(secret.Data, ttest.expectedRootCA.Data) {
				diff := cmp.Diff(secret.Data, ttest.expectedRootCA.Data)
				t.Errorf("got an unexpected secret, diff %s", diff)
			}
			secret = corev1.Secret{}
			if err := test.client.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: constants.ControllerCertificateSecretName}, &secret); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if ttest.expectedControllerCert == nil && len(secret.StringData) != 2 {
				t.Errorf("invalid secret data: %s", secret.StringData)
			}
			if ttest.expectedControllerCert != nil && !cmp.Equal(secret.StringData, ttest.expectedControllerCert.StringData) {
				diff := cmp.Diff(secret.StringData, ttest.expectedControllerCert.StringData)
				t.Errorf("got an unexpected secret, diff %s", diff)
			}
			for webhookConfigName, expectedCABundle := range ttest.expectedWebhooksCABundle {
				if len(expectedCABundle) == 0 {
					expectedCABundle = rootCACertPem
				}
				if err := validateValidatingWebhookConfiguration(ttest.client, webhookConfigName, expectedCABundle); err == nil {
					continue
				}
				if err := validateMutatingWebhookConfiguration(ttest.client, webhookConfigName, expectedCABundle); err == nil {
					continue
				}
				t.Errorf("missing validation or mutation webhook: %s", webhookConfigName)
			}
			if ttest.shouldInitializeCertificates != initialized {
				t.Errorf("CA and/or certificate should not be initialized")
			}
		})
	}
}

func TestConfigureControllerWebhookToUseRootCA(t *testing.T) {
	setUPTest(t)

	var tests = []struct {
		name                     string
		client                   client.Client
		caCertificate            []byte
		validatingWebhookNames   []string
		mutatingWebhookNames     []string
		expectedWebhooksCABundle map[string][]byte
	}{
		{"All webhooks are created",
			fake.NewClientBuilder().WithObjects(validatingWebhook, mutatingWebhook).Build(),
			admissionregCA.CaCert,
			[]string{validatingWebhook.Name},
			[]string{mutatingWebhook.Name},
			map[string][]byte{"validatingWebhookConfig": admissionregCA.CaCert, "mutatingWebhookConfig": admissionregCA.CaCert},
		},
		{"with others webhooks",
			fake.NewClientBuilder().WithObjects(validatingWebhook, mutatingWebhook, otherValidatingWebhook, otherMutatingWebhook).Build(),
			admissionregCA.CaCert,
			[]string{validatingWebhook.Name},
			[]string{mutatingWebhook.Name},
			map[string][]byte{"validatingWebhookConfig": admissionregCA.CaCert, "mutatingWebhookConfig": admissionregCA.CaCert, "otherValidatingWebhookConfig": otherCABundle, "otherMutatingWebhookConfig": otherCABundle},
		},
	}

	for _, test := range tests {
		ttest := test // ensure tt is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			if err := configureControllerValidationWebhooksToUseRootCA(context.TODO(), ttest.client, ttest.caCertificate, ttest.validatingWebhookNames); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if err := configureControllerMutatingWebhooksToUseRootCA(context.TODO(), ttest.client, ttest.caCertificate, ttest.mutatingWebhookNames); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			for webhookConfigName, expectedCABundle := range ttest.expectedWebhooksCABundle {
				if err := validateValidatingWebhookConfiguration(ttest.client, webhookConfigName, expectedCABundle); err == nil {
					continue
				}
				if err := validateMutatingWebhookConfiguration(ttest.client, webhookConfigName, expectedCABundle); err == nil {
					continue
				}
				t.Errorf("missing validation or mutation webhook: %s", webhookConfigName)
			}
		})
	}
}

func validateMutatingWebhookConfiguration(clusterClient client.Client, webhookConfigName string, expectedCABundle []byte) error {
	webhookConfig := admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := clusterClient.Get(context.Background(), client.ObjectKey{Name: webhookConfigName}, &webhookConfig); err == nil {
		for _, webhook := range webhookConfig.Webhooks {
			if !bytes.Equal(webhook.ClientConfig.CABundle, expectedCABundle) {
				diff := cmp.Diff(webhook.ClientConfig.CABundle, expectedCABundle)
				return fmt.Errorf("invalid webhook ca bundle: %s", diff)
			}
		}
	} else {
		return fmt.Errorf("cannot get MutatingWebhookConfiguration: %s", err.Error())
	}
	return nil
}

func validateValidatingWebhookConfiguration(clusterClient client.Client, webhookConfigName string, expectedCABundle []byte) error {
	webhookConfig := admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := clusterClient.Get(context.Background(), client.ObjectKey{Name: webhookConfigName}, &webhookConfig); err == nil {
		for _, webhook := range webhookConfig.Webhooks {
			if !bytes.Equal(webhook.ClientConfig.CABundle, expectedCABundle) {
				diff := cmp.Diff(webhook.ClientConfig.CABundle, expectedCABundle)
				return fmt.Errorf("invalid webhook ca bundle: %s", diff)
			}
		}
	} else {
		return fmt.Errorf("cannot get ValidatingWebhookConfiguration: %s", err.Error())
	}
	return nil
}
