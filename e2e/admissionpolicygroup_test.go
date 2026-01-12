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

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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

func TestAdmissionPolicyGroupController(t *testing.T) {
	policyNamespace := "admission-policy-group-controller-test"

	validatingFeature := features.New("Validating AdmissionPolicyGroup").
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

			// Create validating AdmissionPolicyGroup
			policyName := policiesv1.NewAdmissionPolicyGroupFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyGroupFactory().
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
		Assess("should set the AdmissionPolicyGroup to active sometime after its creation", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value("policyName").(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicyGroup{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicyGroup)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "PolicyGroup should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicyGroup{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicyGroup)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "PolicyGroup should transition to active status")

			return ctx
		}).
		Assess("should create the ValidatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicyGroup)
			policyName := ctx.Value("policyName").(string)
			policyServerName := ctx.Value("policyServerName").(string)

			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: webhookName},
			}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)

				// Verify labels and annotations
				if !verifyWebhookMetadata(w.Labels, w.Annotations, policyName, policyNamespace) {
					return false
				}

				// Verify webhooks
				if len(w.Webhooks) != 1 {
					return false
				}
				if w.Webhooks[0].ClientConfig.Service.Name != "policy-server-"+policyServerName {
					return false
				}
				if len(w.Webhooks[0].MatchConditions) != 1 {
					return false
				}

				return true
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be created with correct details")

			// Verify CA bundle
			caSecret, err := getTestCASecret(ctx, cfg)
			require.NoError(t, err)

			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
				return string(w.Webhooks[0].ClientConfig.CABundle) == string(caSecret.Data[constants.CARootCert])
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should have correct CA bundle")

			return ctx
		}).
		Assess("should reconcile the ValidatingWebhookConfiguration to the original state after some change", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicyGroup)
			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			err := cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)

			// Store original values
			originalLabels := webhook.DeepCopy().Labels
			originalAnnotations := webhook.DeepCopy().Annotations
			originalWebhooks := webhook.DeepCopy().Webhooks

			// Modify the webhook
			delete(webhook.Labels, constants.PartOfLabelKey)
			delete(webhook.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			webhook.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = "invalid-namespace"
			webhook.Webhooks[0].ClientConfig.Service.Name = "invalid-service"
			webhook.Webhooks[0].ClientConfig.CABundle = []byte("invalid")

			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
				return verifyWebhookMetadata(w.Labels, w.Annotations, policy.Name, policyNamespace) &&
					len(w.Webhooks) == 1 &&
					w.Webhooks[0].ClientConfig.Service.Name == originalWebhooks[0].ClientConfig.Service.Name
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled")

			// Test reconciliation when labels and annotations are nil (simulate Kubewarden <= 1.9.0 behavior)
			err = cfg.Client().Resources().Get(ctx, webhookName, "", webhook)
			require.NoError(t, err)
			webhook.Labels = nil
			webhook.Annotations = nil
			err = cfg.Client().Resources().Update(ctx, webhook)
			require.NoError(t, err)

			// Wait for reconciliation
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(webhook, func(object k8s.Object) bool {
				w := object.(*admissionregistrationv1.ValidatingWebhookConfiguration)
				// Re-check everything matches original
				for k, v := range originalLabels {
					if w.Labels[k] != v {
						return false
					}
				}
				for k, v := range originalAnnotations {
					if w.Annotations[k] != v {
						return false
					}
				}
				return true
			}), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled from nil labels/annotations")

			return ctx
		}).
		Assess("should delete the ValidatingWebhookConfiguration when the AdmissionPolicyGroup is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.AdmissionPolicyGroup)

			// Delete the policy
			err := cfg.Client().Resources().Delete(ctx, policy)
			require.NoError(t, err)

			// Wait for webhook to be deleted
			webhookName := policy.GetUniqueName()
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: webhookName},
			}
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(webhook),
				wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be deleted")

			return ctx
		}).
		Feature()

	scheduledFeature := features.New("Scheduled AdmissionPolicyGroup").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Create namespace
			err := createNamespaceWithRetry(ctx, cfg, policyNamespace)
			require.NoError(t, err)

			// Add scheme
			err = policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create AdmissionPolicyGroup with non-existent PolicyServer
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyName := policiesv1.NewAdmissionPolicyGroupFactory().Build().Name
			policy := policiesv1.NewAdmissionPolicyGroupFactory().
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
				&policiesv1.AdmissionPolicyGroup{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicyGroup)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusScheduled
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "PolicyGroup should have scheduled status")

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
				&policiesv1.AdmissionPolicyGroup{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicyGroup)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "PolicyGroup should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.AdmissionPolicyGroup{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: policyNamespace}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.AdmissionPolicyGroup)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "PolicyGroup should transition to active status")

			return ctx
		}).Feature()

	testenv.Test(t, validatingFeature, scheduledFeature)
}
