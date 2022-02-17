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

package policies

import (
	"context"
	"fmt"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/naming"
	"github.com/pkg/errors"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func setPolicyStatus(ctx context.Context, deploymentsNamespace string, client client.Client, apiReader client.Reader, policy policiesv1alpha2.Policy) (ctrl.Result, error) {
	switch policy.GetStatus().PolicyStatus { //nolint:exhaustive
	case "":
		// If the policy status is empty, default to "unscheduled" if a
		// policy server is not assigned. Set to "scheduled" if there is.
		if policy.GetPolicyServer() == "" {
			policy.SetStatus(policiesv1alpha2.PolicyStatusUnscheduled)
		} else {
			policy.SetStatus(policiesv1alpha2.PolicyStatusScheduled)
		}
	case policiesv1alpha2.PolicyStatusUnscheduled:
		// If the policy status is "unscheduled", and now we observe a
		// policy server is assigned, set to "scheduled".
		if policy.GetPolicyServer() != "" {
			policy.SetStatus(policiesv1alpha2.PolicyStatusScheduled)
		}
	case policiesv1alpha2.PolicyStatusScheduled:
		// If the policy status is "scheduled", and now we observe a
		// policy server that exists, set to "pending".
		policyServer := policiesv1alpha2.PolicyServer{}
		if err := apiReader.Get(ctx, types.NamespacedName{Name: policy.GetPolicyServer()}, &policyServer); err == nil {
			policy.SetStatus(policiesv1alpha2.PolicyStatusPending)
		}
	}
	if err := client.Status().Update(ctx, policy); err != nil { //nolint
		// Not critical, continuing since we will update the status at the end again
	}

	policyServerDeployment := appsv1.Deployment{}
	if err := apiReader.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "could not read policy server Deployment")
	}

	policyServerConfigMap := corev1.ConfigMap{}
	if err := apiReader.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerConfigMap); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "could not read policy server ConfigMap")
	}

	policyMap, err := getPolicyMapFromConfigMap(&policyServerConfigMap)
	if err == nil {
		if policyConfig, ok := policyMap[policy.GetUniqueName()]; ok {
			policy.SetPolicyModeStatus(policiesv1alpha2.PolicyModeStatus(policyConfig.PolicyMode))
		} else {
			policy.SetPolicyModeStatus(policiesv1alpha2.PolicyModeStatusUnknown)
		}
	} else {
		policy.SetPolicyModeStatus(policiesv1alpha2.PolicyModeStatusUnknown)
	}

	policyStatus := policy.GetStatus()
	SetPolicyConfigurationCondition(&policyServerConfigMap, &policyServerDeployment, &policyStatus.Conditions)
	SetPolicyUniquenessCondition(ctx, apiReader, &policyServerConfigMap, &policyServerDeployment, &policyStatus.Conditions)

	// Update status
	err = client.Status().Update(ctx, policy)
	return ctrl.Result{}, errors.Wrap(err, "failed to update status")
}

func reconcilePolicy(ctx context.Context, client client.Client, reconciler admission.Reconciler, admissionPolicy policiesv1alpha2.Policy) (ctrl.Result, error) {
	secret := corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: reconciler.DeploymentsNamespace, Name: admissionPolicy.GetPolicyServer()}, &secret); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "cannot find policy server secret")
	}
	if admissionPolicy.IsMutating() {
		if err := reconciler.ReconcileMutatingWebhookConfiguration(ctx, admissionPolicy, &secret); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error reconciling mutating webhook")
		}
	} else {
		if err := reconciler.ReconcileValidatingWebhookConfiguration(ctx, admissionPolicy, &secret); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error reconciling validating webhook")
		}
	}
	return setPolicyStatus(ctx, reconciler.DeploymentsNamespace, client, reconciler.APIReader, admissionPolicy)
}

func reconcilePolicyDeletion(ctx context.Context, client client.Client, admissionPolicy policiesv1alpha2.Policy) (ctrl.Result, error) {
	if admissionPolicy.IsMutating() {
		if err := reconcileMutatingWebhook(ctx, client, admissionPolicy); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := reconcileValidatingWebhook(ctx, client, admissionPolicy); err != nil {
			return ctrl.Result{}, err
		}
	}
	controllerutil.RemoveFinalizer(admissionPolicy, constants.KubewardenFinalizer)
	if err := client.Update(ctx, admissionPolicy); err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot update admission policy: %w", err)
	}
	return ctrl.Result{}, nil
}

func reconcileValidatingWebhook(ctx context.Context, client client.Client, admissionPolicy policiesv1alpha2.Policy) error {
	webhook := admissionregistrationv1.ValidatingWebhookConfiguration{}
	err := client.Get(ctx, types.NamespacedName{Name: admissionPolicy.GetUniqueName()}, &webhook)
	if err == nil {
		if err := client.Delete(ctx, &webhook); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("cannot delete validating webhook: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve validating webhook: %w", err)
	}
	return nil
}

func reconcileMutatingWebhook(ctx context.Context, client client.Client, admissionPolicy policiesv1alpha2.Policy) error {
	webhook := admissionregistrationv1.MutatingWebhookConfiguration{}
	err := client.Get(ctx, types.NamespacedName{Name: admissionPolicy.GetUniqueName()}, &webhook)
	if err == nil {
		if err := client.Delete(ctx, &webhook); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("cannot delete mutating webhook: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("cannot retrieve mutating webhook: %w", err)
	}
	return nil
}
