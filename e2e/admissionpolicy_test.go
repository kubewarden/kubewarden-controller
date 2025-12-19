/*
Copyright 2022.

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

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const (
	testTimeout      = 5 * time.Minute
	testPollInterval = 1 * time.Second
)

func TestAdmissionPolicyController(t *testing.T) {
	policyNamespace := "admission-policy-controller-test"

	validatingFeature := features.New("Validating AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer and wait for it to be ready
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyServerName", policyServerName)

			// Create validating AdmissionPolicy
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyName", policyName)
			ctx = context.WithValue(ctx, "policy", policy)

			return ctx
		}).
		Assess("should set the AdmissionPolicy to active sometime after its creation", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value("policyName").(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Assess("should create the ValidatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicy)
			policyName := ctx.Value("policyName").(string)
			policyServerName := ctx.Value("policyServerName").(string)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: webhookName},
			}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)

				// Verify labels
				if w.Labels[constants.PartOfLabelKey] != constants.PartOfLabelValue {
					return false
				}

				// Verify annotations
				if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != policyName {
					return false
				}
				if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != policyNamespace {
					return false
				}

				// Verify webhooks
				if len(w.Webhooks) != 1 {
					return false
				}
				if w.Webhooks[0].ClientConfig.Service.Name != "policy-server-"+policyServerName {
					return false
				}
				if *w.Webhooks[0].ClientConfig.Service.Port != int32(constants.PolicyServerServicePort) {
					return false
				}
				if len(w.Webhooks[0].MatchConditions) != 1 {
					return false
				}

				return true
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be created with correct configuration")

			// Verify CA bundle
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			caSecret, err := getTestCASecret(ctx, cfg)
			require.NoError(t, err)
			require.Equal(t, caSecret.Data[constants.CARootCert], webhook.Webhooks[0].ClientConfig.CABundle)

			return ctx
		}).
		Assess("should reconcile the ValidatingWebhookConfiguration to the original state after some change", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicy)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			// Store original values
			originalLabels := make(map[string]string)
			for k, v := range webhook.Labels {
				originalLabels[k] = v
			}
			originalAnnotations := make(map[string]string)
			for k, v := range webhook.Annotations {
				originalAnnotations[k] = v
			}
			originalServiceName := webhook.Webhooks[0].ClientConfig.Service.Name
			originalCABundle := webhook.Webhooks[0].ClientConfig.CABundle

			// Modify the webhook
			delete(webhook.Labels, constants.PartOfLabelKey)
			delete(webhook.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			webhook.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = "wrong-namespace"
			webhook.Webhooks[0].ClientConfig.Service.Name = "wrong-service"
			webhook.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)

					if w.Labels[constants.PartOfLabelKey] != originalLabels[constants.PartOfLabelKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] {
						return false
					}
					if w.Webhooks[0].ClientConfig.Service.Name != originalServiceName {
						return false
					}
					if string(w.Webhooks[0].ClientConfig.CABundle) != string(originalCABundle) {
						return false
					}
					return true
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled to original state")

			// Test reconciliation when labels and annotations are nil (simulate Kubewarden <= 1.9.0 behavior)
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			webhook.Labels = nil
			webhook.Annotations = nil
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
					return w.Labels != nil && w.Annotations != nil &&
						w.Labels[constants.PartOfLabelKey] == originalLabels[constants.PartOfLabelKey] &&
						w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] == originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey]
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled when labels/annotations are nil")

			return ctx
		}).
		Assess("should delete the ValidatingWebhookConfiguration when the AdmissionPolicy is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicy)
			webhookName := policy.GetUniqueName()

			// Delete the policy
			err := cfg.Client().Resources().Delete(ctx, policy)
			require.NoError(t, err)

			// Wait for webhook to be deleted
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(
				&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be deleted")

			return ctx
		}).
		Feature()

	mutatingFeature := features.New("Mutating AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer and wait for it to be ready
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyServerName", policyServerName)

			// Create mutating AdmissionPolicy
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				WithMutating(true).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyName", policyName)
			ctx = context.WithValue(ctx, "policy", policy)

			return ctx
		}).
		Assess("should set the AdmissionPolicy to active", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value("policyName").(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Assess("should create the MutatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicy)
			policyName := ctx.Value("policyName").(string)
			policyServerName := ctx.Value("policyServerName").(string)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: webhookName},
			}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.MutatingWebhookConfiguration)

				// Verify labels
				if w.Labels[constants.PartOfLabelKey] != constants.PartOfLabelValue {
					return false
				}

				// Verify annotations
				if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != policyName {
					return false
				}
				if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != policyNamespace {
					return false
				}

				// Verify webhooks
				if len(w.Webhooks) != 1 {
					return false
				}
				if w.Webhooks[0].ClientConfig.Service.Name != "policy-server-"+policyServerName {
					return false
				}
				if *w.Webhooks[0].ClientConfig.Service.Port != int32(constants.PolicyServerServicePort) {
					return false
				}
				if len(w.Webhooks[0].MatchConditions) != 1 {
					return false
				}

				return true
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be created with correct configuration")

			// Verify CA bundle
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			caSecret, err := getTestCASecret(ctx, cfg)
			require.NoError(t, err)
			require.Equal(t, caSecret.Data[constants.CARootCert], webhook.Webhooks[0].ClientConfig.CABundle)

			return ctx
		}).
		Assess("should reconcile the MutatingWebhookConfiguration to the original state after some change", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicy)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			// Store original values
			originalLabels := make(map[string]string)
			for k, v := range webhook.Labels {
				originalLabels[k] = v
			}
			originalAnnotations := make(map[string]string)
			for k, v := range webhook.Annotations {
				originalAnnotations[k] = v
			}
			originalServiceName := webhook.Webhooks[0].ClientConfig.Service.Name
			originalCABundle := webhook.Webhooks[0].ClientConfig.CABundle

			// Modify the webhook
			delete(webhook.Labels, constants.PartOfLabelKey)
			delete(webhook.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			webhook.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = "wrong-namespace"
			webhook.Webhooks[0].ClientConfig.Service.Name = "wrong-service"
			webhook.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.MutatingWebhookConfiguration)

					if w.Labels[constants.PartOfLabelKey] != originalLabels[constants.PartOfLabelKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey] {
						return false
					}
					if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != originalAnnotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] {
						return false
					}
					if w.Webhooks[0].ClientConfig.Service.Name != originalServiceName {
						return false
					}
					if string(w.Webhooks[0].ClientConfig.CABundle) != string(originalCABundle) {
						return false
					}
					return true
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be reconciled to original state")

			// Test reconciliation when labels and annotations are nil (simulate Kubewarden <= 1.9.0 behavior)
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			webhook.Labels = nil
			webhook.Annotations = nil
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
				func(object k8s.Object) bool {
					w := object.(*admissionregistrationv1.MutatingWebhookConfiguration)
					return w.Labels != nil && w.Annotations != nil &&
						w.Labels[constants.PartOfLabelKey] == originalLabels[constants.PartOfLabelKey] &&
						w.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey] == originalAnnotations[constants.WebhookConfigurationPolicyNameAnnotationKey]
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be reconciled when labels/annotations are nil")

			return ctx
		}).
		Assess("should delete the MutatingWebhookConfiguration when the AdmissionPolicy is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicy)
			webhookName := policy.GetUniqueName()

			// Delete the policy
			err := cfg.Client().Resources().Delete(ctx, policy)
			require.NoError(t, err)

			// Wait for webhook to be deleted
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(
				&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be deleted")

			return ctx
		}).Feature()

	// TODO: REMOVE THIS TEST - IT'S NEVER GOING TO PASS, IT'S WRONG

	// unscheduledFeature := features.New("Unscheduled AdmissionPolicy").
	// 	Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	// 		// Create namespace
	// 		err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
	// 		require.NoError(t, err)

	// 		// Add scheme
	// 		err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
	// 		require.NoError(t, err)

	// 		return ctx
	// 	}).
	// 	Assess("should set policy status to unscheduled when creating an AdmissionPolicy without a PolicyServer assigned", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	// 		policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
	// 		policy := policiesv1.NewAdmissionPolicyFactory().
	// 			WithName(policyName).
	// 			WithNamespace(policyNamespace).
	// 			WithPolicyServer("i-do-not-exist").
	// 			Build()

	// 		err := cfg.Client().Resources().Create(ctx, policy)
	// 		if err != nil && !apierrors.IsAlreadyExists(err) {
	// 			require.NoError(t, err)
	// 		}

	// 		// Add debug logging to see what status we're getting
	// 		err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
	// 			&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
	// 			func(object k8s.Object) bool {
	// 				p := object.(*policiesv1.AdmissionPolicy)
	// 				t.Logf("Current policy status: %s", p.Status.PolicyStatus)
	// 				return p.Status.PolicyStatus == policiesv1.PolicyStatusUnscheduled
	// 			},
	// 		), wait.WithTimeout(30*time.Second), wait.WithInterval(testPollInterval))
	// 		//), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))

	// 		// If it fails, get the final status for debugging
	// 		if err != nil {
	// 			finalPolicy := &policiesv1.AdmissionPolicy{}
	// 			_ = cfg.Client().Resources().Get(ctx, policyName, policyNamespace, finalPolicy)
	// 			t.Logf("Final policy status: %s, PolicyServer: %s", finalPolicy.Status.PolicyStatus, finalPolicy.Spec.PolicyServer)
	// 		}

	// 		require.NoError(t, err, "Policy should have unscheduled status")

	// 		return ctx
	// 	}).Feature()

	scheduledFeature := features.New("Scheduled AdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create AdmissionPolicy with non-existent PolicyServer
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyName := policiesv1.NewAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyFactory().
				WithName(policyName).
				WithNamespace(policyNamespace).
				WithPolicyServer(policyServerName).
				Build()

			err = cfg.Client().Resources().Create(ctx, policy)
			if err != nil && !apierrors.IsAlreadyExists(err) {
				require.NoError(t, err)
			}

			ctx = context.WithValue(ctx, "policyName", policyName)
			ctx = context.WithValue(ctx, "policyServerName", policyServerName)

			return ctx
		}).
		Assess("should set the policy status to scheduled", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value("policyName").(string)

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusScheduled
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should have scheduled status")

			return ctx
		}).
		Assess("should set the policy status to active when the PolicyServer is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyServerName := ctx.Value("policyServerName").(string)
			policyName := ctx.Value("policyName").(string)

			// Create PolicyServer
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err := cfg.Client().Resources().Create(ctx, policyServer)
			if err != nil && !apierrors.IsAlreadyExists(err) {
				require.NoError(t, err)
			}

			// Wait for policy status to be pending
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).Feature()

	testenv.Test(t, validatingFeature, mutatingFeature, scheduledFeature)
}

// Helper functions

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
			return false, nil
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
