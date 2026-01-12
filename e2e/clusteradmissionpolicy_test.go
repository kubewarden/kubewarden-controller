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

func TestClusterAdmissionPolicyController(t *testing.T) {
	timeoutValidationFeature := features.New("ClusterAdmissionPolicy timeout validation").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Add scheme
			err := policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyServerName", policyServerName)

			return ctx
		}).
		Assess("should fail CRD validation because of too low TimeoutSeconds", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyServerName := ctx.Value("policyServerName").(string)
			policyName := policiesv1.NewClusterAdmissionPolicyFactory().Build().Name

			underMinTimeout := int32(1)
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policyName).
				WithPolicyServer(policyServerName).
				WithTimeoutSeconds(&underMinTimeout).
				Build()

			err := cfg.Client().Resources().Create(ctx, policy)
			require.Error(t, err, "Creating policy with too low TimeoutSeconds should fail")

			return ctx
		}).
		Assess("should fail CRD validation because of too low TimeoutEvalSeconds", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyServerName := ctx.Value("policyServerName").(string)
			policyName := policiesv1.NewClusterAdmissionPolicyFactory().Build().Name

			underMinTimeout := int32(1)
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policyName).
				WithPolicyServer(policyServerName).
				WithTimeoutEvalSeconds(&underMinTimeout).
				Build()

			err := cfg.Client().Resources().Create(ctx, policy)
			require.Error(t, err, "Creating policy with too low TimeoutEvalSeconds should fail")

			return ctx
		}).
		Feature()

	validatingFeature := features.New("Validating ClusterAdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Add scheme
			err := policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer and wait for it to be ready
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyServerName", policyServerName)

			// Create validating ClusterAdmissionPolicy
			policyName := policiesv1.NewClusterAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policyName).
				WithPolicyServer(policyServerName).
				WithMutating(false).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyName", policyName)
			ctx = context.WithValue(ctx, "policy", policy)

			return ctx
		}).
		Assess("should set the ClusterAdmissionPolicy to active", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value("policyName").(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Assess("should create the ValidatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.ClusterAdmissionPolicy)
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
				if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != "" {
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

				// Verify namespace selector excludes the deployments namespace
				hasNamespaceSelector := false
				for _, expr := range w.Webhooks[0].NamespaceSelector.MatchExpressions {
					if expr.Key == "kubernetes.io/metadata.name" &&
						expr.Operator == "NotIn" &&
						len(expr.Values) == 1 &&
						expr.Values[0] == namespace {
						hasNamespaceSelector = true
						break
					}
				}
				if !hasNamespaceSelector {
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
			policy := ctx.Value("policy").(*policiesv1.ClusterAdmissionPolicy)

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
					if w.Webhooks[0].ClientConfig.Service.Name != originalWebhooks[0].ClientConfig.Service.Name {
						return false
					}
					if string(w.Webhooks[0].ClientConfig.CABundle) != string(originalWebhooks[0].ClientConfig.CABundle) {
						return false
					}
					return true
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "ValidatingWebhookConfiguration should be reconciled to original state")

			return ctx
		}).
		Assess("should delete the ValidatingWebhookConfiguration when the ClusterAdmissionPolicy is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.ClusterAdmissionPolicy)
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

	mutatingFeature := features.New("Mutating ClusterAdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Add scheme
			err := policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create PolicyServer and wait for it to be ready
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyServer := policiesv1.NewPolicyServerFactory().
				WithName(policyServerName).
				Build()
			err = createPolicyServerAndWaitForItsService(ctx, cfg, policyServer)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyServerName", policyServerName)

			// Create mutating ClusterAdmissionPolicy
			policyName := policiesv1.NewClusterAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policyName).
				WithPolicyServer(policyServerName).
				WithMutating(true).
				Build()
			err = cfg.Client().Resources().Create(ctx, policy)
			require.NoError(t, err)

			ctx = context.WithValue(ctx, "policyName", policyName)
			ctx = context.WithValue(ctx, "policy", policy)

			return ctx
		}).
		Assess("should set the ClusterAdmissionPolicy to active", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policyName := ctx.Value("policyName").(string)

			// Wait for policy status to be pending
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Assess("should create the MutatingWebhookConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.ClusterAdmissionPolicy)
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
				if w.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] != "" {
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

				// Verify namespace selector excludes the deployments namespace
				hasNamespaceSelector := false
				for _, expr := range w.Webhooks[0].NamespaceSelector.MatchExpressions {
					if expr.Key == "kubernetes.io/metadata.name" &&
						expr.Operator == "NotIn" &&
						len(expr.Values) == 1 &&
						expr.Values[0] == namespace {
						hasNamespaceSelector = true
						break
					}
				}
				if !hasNamespaceSelector {
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
			policy := ctx.Value("policy").(*policiesv1.ClusterAdmissionPolicy)

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
					if w.Webhooks[0].ClientConfig.Service.Name != originalWebhooks[0].ClientConfig.Service.Name {
						return false
					}
					if string(w.Webhooks[0].ClientConfig.CABundle) != string(originalWebhooks[0].ClientConfig.CABundle) {
						return false
					}
					return true
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "MutatingWebhookConfiguration should be reconciled to original state")

			return ctx
		}).
		Assess("should delete the MutatingWebhookConfiguration when the ClusterAdmissionPolicy is deleted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			policy := ctx.Value("policy").(*policiesv1.ClusterAdmissionPolicy)
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
		}).
		Feature()

	scheduledFeature := features.New("Scheduled ClusterAdmissionPolicy").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Add scheme
			err := policiesv1.AddToScheme(cfg.Client().Resources().GetScheme())
			require.NoError(t, err)

			// Create ClusterAdmissionPolicy with non-existent PolicyServer
			policyServerName := policiesv1.NewPolicyServerFactory().Build().Name
			policyName := policiesv1.NewClusterAdmissionPolicyFactory().Build().Name
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policyName).
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
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
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
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusPending
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to pending status")

			// Wait for policy status to be active
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(
				&policiesv1.ClusterAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName}},
				func(object k8s.Object) bool {
					p := object.(*policiesv1.ClusterAdmissionPolicy)
					return p.Status.PolicyStatus == policiesv1.PolicyStatusActive
				},
			), wait.WithTimeout(testTimeout), wait.WithInterval(testPollInterval))
			require.NoError(t, err, "Policy should transition to active status")

			return ctx
		}).
		Feature()

	testenv.Test(t, timeoutValidationFeature, validatingFeature, mutatingFeature, scheduledFeature)
}
