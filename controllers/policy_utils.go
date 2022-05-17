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

package controllers

import (
	"context"
	"fmt"
	"time"

	v1alpha2 "github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/naming"
	"github.com/pkg/errors"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func setPolicyStatus(ctx context.Context, deploymentsNamespace string, apiReader client.Reader, policy v1alpha2.Policy) error {
	policyServerDeployment := appsv1.Deployment{}
	if err := apiReader.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		return errors.Wrap(err, "could not get policy server deployment")
	}

	policyServerConfigMap := corev1.ConfigMap{}
	if err := apiReader.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerConfigMap); err != nil {
		return errors.Wrap(err, "could not get configmap")
	}

	policyMap, err := getPolicyMapFromConfigMap(&policyServerConfigMap)
	if err == nil {
		if policyConfig, ok := policyMap[policy.GetUniqueName()]; ok {
			policy.SetPolicyModeStatus(v1alpha2.PolicyModeStatus(policyConfig.PolicyMode))
		} else {
			policy.SetPolicyModeStatus(v1alpha2.PolicyModeStatusUnknown)
		}
	} else {
		policy.SetPolicyModeStatus(v1alpha2.PolicyModeStatusUnknown)
	}

	policyStatus := policy.GetStatus()
	SetPolicyConfigurationCondition(&policyServerConfigMap, &policyServerDeployment, &policyStatus.Conditions)

	return nil
}

func startReconciling(ctx context.Context, client client.Client, reconciler admission.Reconciler, policy v1alpha2.Policy) (ctrl.Result, error) {
	if policy.GetDeletionTimestamp() != nil {
		return reconcilePolicyDeletion(ctx, client, policy)
	}

	reconcileResult, reconcileErr := reconcilePolicy(ctx, client, reconciler, policy)

	_ = setPolicyStatus(ctx, reconciler.DeploymentsNamespace, reconciler.APIReader, policy)
	if err := client.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("update admission policy status error: %w", err)
	}

	return reconcileResult, reconcileErr
}

func reconcilePolicy(ctx context.Context, client client.Client, reconciler admission.Reconciler, policy v1alpha2.Policy) (ctrl.Result, error) {
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(v1alpha2.PolicyActive),
			Status:  metav1.ConditionFalse,
			Reason:  "PolicyActive",
			Message: "The policy webhook has not been created",
		},
	)
	if policy.GetPolicyServer() == "" {
		policy.SetStatus(v1alpha2.PolicyStatusUnscheduled)
		return ctrl.Result{}, nil
	}

	policyServer, err := getPolicyServer(ctx, client, policy)
	if err != nil {
		policy.SetStatus(v1alpha2.PolicyStatusScheduled)
		//lint:ignore nilerr set status to scheduled if policyServer can't be retrieved, and stop reconciling
		return ctrl.Result{}, nil
	}
	if policy.GetStatus().PolicyStatus != v1alpha2.PolicyStatusActive {
		policy.SetStatus(v1alpha2.PolicyStatusPending)
	}

	policyServerDeployment := appsv1.Deployment{}
	if err := reconciler.APIReader.Get(ctx, types.NamespacedName{Namespace: reconciler.DeploymentsNamespace, Name: naming.PolicyServerDeploymentNameForPolicyServerName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, errors.Wrap(err, "could not read policy server Deployment")
	}

	if !isPolicyUniquelyReachable(ctx, client, &policyServerDeployment, policy.GetUniqueName()) {
		apimeta.SetStatusCondition(
			&policy.GetStatus().Conditions,
			metav1.Condition{
				Type:    string(v1alpha2.PolicyUniquelyReachable),
				Status:  metav1.ConditionFalse,
				Reason:  "LatestReplicaSetIsNotUniquelyReachable",
				Message: "The latest replica set is not uniquely reachable",
			},
		)
		return ctrl.Result{Requeue: true, RequeueAfter: 2 * time.Second}, nil
	}

	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(v1alpha2.PolicyUniquelyReachable),
			Status:  metav1.ConditionTrue,
			Reason:  "LatestReplicaSetIsUniquelyReachable",
			Message: "The latest replica set is uniquely reachable",
		},
	)

	secret := corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: reconciler.DeploymentsNamespace, Name: constants.PolicyServerCARootSecretName}, &secret); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "cannot find policy server secret")
	}

	if policy.IsMutating() {
		if err := reconciler.ReconcileMutatingWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error reconciling mutating webhook")
		}
	} else {
		if err := reconciler.ReconcileValidatingWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error reconciling validating webhook")
		}
	}
	setPolicyAsActive(policy)

	return ctrl.Result{}, nil
}

func setPolicyAsActive(policy v1alpha2.Policy) {
	policy.SetStatus(v1alpha2.PolicyStatusActive)
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(v1alpha2.PolicyActive),
			Status:  metav1.ConditionTrue,
			Reason:  "PolicyActive",
			Message: "The policy webhook has been created",
		},
	)
}

func getPolicyServer(ctx context.Context, client client.Client, policy v1alpha2.Policy) (*v1alpha2.PolicyServer, error) {
	policyServer := v1alpha2.PolicyServer{}
	if err := client.Get(ctx, types.NamespacedName{Name: policy.GetPolicyServer()}, &policyServer); err != nil {
		return nil, errors.Wrap(err, "could not get policy server")
	}
	return &policyServer, nil
}

func reconcilePolicyDeletion(ctx context.Context, client client.Client, policy v1alpha2.Policy) (ctrl.Result, error) {
	if policy.IsMutating() {
		if err := reconcileMutatingWebhook(ctx, client, policy); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := reconcileValidatingWebhook(ctx, client, policy); err != nil {
			return ctrl.Result{}, err
		}
	}
	controllerutil.RemoveFinalizer(policy, constants.KubewardenFinalizer)
	if err := client.Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot update admission policy: %w", err)
	}
	return ctrl.Result{}, nil
}

func reconcileValidatingWebhook(ctx context.Context, client client.Client, admissionPolicy v1alpha2.Policy) error {
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

func reconcileMutatingWebhook(ctx context.Context, client client.Client, admissionPolicy v1alpha2.Policy) error {
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
