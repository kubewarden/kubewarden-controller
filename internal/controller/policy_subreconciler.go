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

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	"github.com/kubewarden/kubewarden-controller/internal/metrics"
)

type policySubReconciler struct {
	client.Client
	Log                                        logr.Logger
	deploymentsNamespace                       string
	featureGateAdmissionWebhookMatchConditions bool
}

func (r *policySubReconciler) reconcile(ctx context.Context, policy policiesv1.Policy) (ctrl.Result, error) {
	if policy.GetDeletionTimestamp() != nil {
		return r.reconcilePolicyDeletion(ctx, policy)
	}

	reconcileResult, reconcileErr := r.reconcilePolicy(ctx, policy)

	if err := r.setPolicyModeStatus(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("error setting policy status: %w", err)
	}

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("update admission policy status error: %w", err)
	}

	// record policy count metric
	if err := metrics.RecordPolicyCount(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to record policy mestrics: %w", err)
	}

	return reconcileResult, reconcileErr
}

func (r *policySubReconciler) reconcilePolicy(ctx context.Context, policy policiesv1.Policy) (ctrl.Result, error) {
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyActive),
			Status:  metav1.ConditionFalse,
			Reason:  "PolicyActive",
			Message: "The policy webhook has not been created",
		},
	)
	if policy.GetPolicyServer() == "" {
		policy.SetStatus(policiesv1.PolicyStatusUnscheduled)
		return ctrl.Result{}, nil
	}

	policyServer, err := r.getPolicyServer(ctx, policy)
	if err != nil {
		policy.SetStatus(policiesv1.PolicyStatusScheduled)
		//nolint:nilerr // set status to scheduled if policyServer can't be retrieved, and stop reconciling
		return ctrl.Result{}, nil
	}
	if policy.GetStatus().PolicyStatus != policiesv1.PolicyStatusActive {
		policy.SetStatus(policiesv1.PolicyStatusPending)
	}

	policyServerDeployment := appsv1.Deployment{}
	if err = r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: policyServerDeploymentName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, errors.Join(errors.New("could not read policy server Deployment"), err)
	}

	if !r.isPolicyUniquelyReachable(ctx, &policyServerDeployment, policy.GetUniqueName()) {
		apimeta.SetStatusCondition(
			&policy.GetStatus().Conditions,
			metav1.Condition{
				Type:    string(policiesv1.PolicyUniquelyReachable),
				Status:  metav1.ConditionFalse,
				Reason:  "LatestReplicaSetIsNotUniquelyReachable",
				Message: "The latest replica set is not uniquely reachable",
			},
		)
		return ctrl.Result{Requeue: true, RequeueAfter: constants.TimeToRequeuePolicyReconciliation}, nil
	}

	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyUniquelyReachable),
			Status:  metav1.ConditionTrue,
			Reason:  "LatestReplicaSetIsUniquelyReachable",
			Message: "The latest replica set is uniquely reachable",
		},
	)

	secret := corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: constants.CARootSecretName}, &secret); err != nil {
		return ctrl.Result{}, errors.Join(errors.New("cannot find policy server secret"), err)
	}

	if policy.IsMutating() {
		if err = r.reconcileMutatingWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
			return ctrl.Result{}, errors.Join(errors.New("error reconciling mutating webhook"), err)
		}
	} else {
		if err = r.reconcileValidatingWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
			return ctrl.Result{}, errors.Join(errors.New("error reconciling validating webhook"), err)
		}
	}
	setPolicyAsActive(policy)

	return ctrl.Result{}, nil
}

func (r *policySubReconciler) reconcilePolicyDeletion(ctx context.Context, policy policiesv1.Policy) (ctrl.Result, error) {
	if policy.IsMutating() {
		if err := r.reconcileMutatingWebhookConfigurationDeletion(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := r.reconcileValidatingWebhookConfigurationDeletion(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	}
	// Remove the old finalizer used to ensure that the policy server created
	// before this controller version is delete as well. As the upgrade path
	// supported by the Kubewarden project does not allow jumping versions, we
	// can safely remove this line of code after a few releases.
	controllerutil.RemoveFinalizer(policy, constants.KubewardenFinalizerPre114)
	controllerutil.RemoveFinalizer(policy, constants.KubewardenFinalizer)
	if err := r.Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot update admission policy: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *policySubReconciler) setPolicyModeStatus(ctx context.Context, policy policiesv1.Policy) error {
	policyServerDeployment := appsv1.Deployment{}
	policyServerDeploymentName := policyServerDeploymentName(policy.GetPolicyServer())

	if err := r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: policyServerDeploymentName}, &policyServerDeployment); err != nil {
		if apierrors.IsNotFound(err) {
			// If the policy server deployment is not found, the policy is not scheduled
			return nil
		}

		return errors.Join(errors.New("could not get policy server deployment"), err)
	}

	policyServerConfigMap := corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: policyServerDeploymentName}, &policyServerConfigMap); err != nil {
		return errors.Join(errors.New("could not get configmap"), err)
	}

	policyMap, err := getPolicyMapFromConfigMap(&policyServerConfigMap)
	if err == nil {
		if policyConfig, ok := policyMap[policy.GetUniqueName()]; ok {
			policy.SetPolicyModeStatus(policiesv1.PolicyModeStatus(policyConfig.PolicyMode))
		} else {
			policy.SetPolicyModeStatus(policiesv1.PolicyModeStatusUnknown)
		}
	} else {
		policy.SetPolicyModeStatus(policiesv1.PolicyModeStatusUnknown)
	}

	policyStatus := policy.GetStatus()
	setPolicyConfigurationCondition(&policyServerConfigMap, &policyServerDeployment, &policyStatus.Conditions)

	return nil
}

func (r *policySubReconciler) getPolicyServer(ctx context.Context, policy policiesv1.Policy) (*policiesv1.PolicyServer, error) {
	policyServer := policiesv1.PolicyServer{}
	if err := r.Get(ctx, types.NamespacedName{Name: policy.GetPolicyServer()}, &policyServer); err != nil {
		return nil, errors.Join(errors.New("could not get policy server"), err)
	}
	return &policyServer, nil
}

func (r *policySubReconciler) isPolicyUniquelyReachable(ctx context.Context, policyServerDeployment *appsv1.Deployment, policyName string) bool {
	configMap := corev1.ConfigMap{}

	err := r.Get(ctx, client.ObjectKey{
		Namespace: policyServerDeployment.Namespace,
		Name:      policyServerDeployment.Name, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return false
	}

	if !isPolicyInConfigMap(configMap, policyName) {
		return false
	}

	replicaSets := appsv1.ReplicaSetList{}
	if err = r.List(ctx, &replicaSets, client.MatchingLabels{constants.PolicyServerLabelKey: policyServerDeployment.Labels[constants.PolicyServerLabelKey]}); err != nil {
		return false
	}
	podTemplateHash := ""
	for index := range replicaSets.Items {
		if isLatestReplicaSetFromPolicyServerDeployment(&replicaSets.Items[index], policyServerDeployment, configMap.ResourceVersion) {
			podTemplateHash = replicaSets.Items[index].Labels[appsv1.DefaultDeploymentUniqueLabelKey]
			break
		}
	}
	if podTemplateHash == "" {
		return false
	}
	pods := corev1.PodList{}
	if err = r.List(ctx, &pods, client.MatchingLabels{constants.PolicyServerLabelKey: policyServerDeployment.Labels[constants.PolicyServerLabelKey]}); err != nil {
		return false
	}
	if len(pods.Items) == 0 {
		return false
	}
	for _, pod := range pods.Items {
		if pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey] != podTemplateHash || !isPodReady(pod) {
			return false
		}
	}
	return true
}

func isLatestReplicaSetFromPolicyServerDeployment(replicaSet *appsv1.ReplicaSet, policyServerDeployment *appsv1.Deployment, configMapVersion string) bool {
	return replicaSet.Annotations[constants.KubernetesRevisionAnnotation] == policyServerDeployment.Annotations[constants.KubernetesRevisionAnnotation] &&
		replicaSet.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] == configMapVersion
}

func isPolicyInConfigMap(configMap corev1.ConfigMap, policyName string) bool {
	policies, err := getPolicyMapFromConfigMap(&configMap)
	if err != nil {
		return false
	}
	if _, ok := policies[policyName]; ok {
		return true
	}

	return false
}

func isPodReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == "Ready" {
			return condition.Status == "True"
		}
	}
	return false
}

func findPoliciesForConfigMap(object client.Object) []reconcile.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return []reconcile.Request{}
	}
	if _, isKubewardenConfigmap := configMap.Labels[constants.PolicyServerLabelKey]; !isKubewardenConfigmap {
		return []reconcile.Request{}
	}
	policyMap, err := getPolicyMapFromConfigMap(configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return policyMap.toAdmissionPolicyReconcileRequests()
}

func findClusterPoliciesForConfigMap(object client.Object) []reconcile.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return []reconcile.Request{}
	}
	policyMap, err := getPolicyMapFromConfigMap(configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return policyMap.toClusterAdmissionPolicyReconcileRequests()
}

func findPoliciesForPod(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerName, isKubewardenPod := pod.Labels[constants.PolicyServerLabelKey]
	if !isKubewardenPod || pod.DeletionTimestamp != nil {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := policyServerDeploymentName(policyServerName)
	configMap := corev1.ConfigMap{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: pod.ObjectMeta.Namespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return findPoliciesForConfigMap(&configMap)
}

func findClusterPoliciesForPod(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerName, ok := pod.Labels[constants.PolicyServerLabelKey]
	if !ok {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := policyServerDeploymentName(policyServerName)
	configMap := corev1.ConfigMap{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: pod.ObjectMeta.Namespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return findClusterPoliciesForConfigMap(&configMap)
}

func findClusterPolicyForWebhookConfiguration(webhookConfiguration client.Object, isGroup bool, log logr.Logger) []reconcile.Request {
	if !hasKubewardenLabel(webhookConfiguration.GetLabels()) {
		return []reconcile.Request{}
	}

	if isGroup && !hasGroupAnnotation(webhookConfiguration.GetAnnotations()) {
		return []reconcile.Request{}
	}

	policyScope, found := webhookConfiguration.GetLabels()[constants.WebhookConfigurationPolicyScopeLabelKey]
	if !found {
		log.Info("Found a webhook configuration without a scope label, reconciling it",
			"name", webhookConfiguration.GetName())
		return []reconcile.Request{}
	}

	// Filter out AdmissionPolicies
	if policyScope != constants.ClusterPolicyScope {
		return []reconcile.Request{}
	}

	policyName, found := webhookConfiguration.GetAnnotations()[constants.WebhookConfigurationPolicyNameAnnotationKey]
	if !found {
		log.Info("Found a webhook configuration without a policy name annotation, reconciling it",
			"name", webhookConfiguration.GetName())
		return []reconcile.Request{}
	}

	return []reconcile.Request{
		{
			NamespacedName: client.ObjectKey{
				Name: policyName,
			},
		},
	}
}

func findPolicyForWebhookConfiguration(webhookConfiguration client.Object, isGroup bool, log logr.Logger) []reconcile.Request {
	if !hasKubewardenLabel(webhookConfiguration.GetLabels()) {
		return []reconcile.Request{}
	}

	if isGroup && !hasGroupAnnotation(webhookConfiguration.GetAnnotations()) {
		return []reconcile.Request{}
	}

	policyScope, found := webhookConfiguration.GetLabels()[constants.WebhookConfigurationPolicyScopeLabelKey]
	if !found {
		log.Info("Found a webhook configuration without a scope label, reconciling it", "name", webhookConfiguration.GetName())
		return []reconcile.Request{}
	}

	// Filter out ClusterAdmissionPolicies
	if policyScope != constants.NamespacePolicyScope {
		return []reconcile.Request{}
	}

	policyNamespace, found := webhookConfiguration.GetAnnotations()[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]
	if !found {
		log.Info("Found a webhook configuration without a namespace annotation, reconciling it", "name", webhookConfiguration.GetName())
		return []reconcile.Request{}
	}

	policyName, found := webhookConfiguration.GetAnnotations()[constants.WebhookConfigurationPolicyNameAnnotationKey]
	if !found {
		log.Info("Found a webhook configuration without a policy name annotation, reconciling it", "name", webhookConfiguration.GetName())
		return []reconcile.Request{}
	}

	return []reconcile.Request{
		{
			NamespacedName: client.ObjectKey{
				Name:      policyName,
				Namespace: policyNamespace,
			},
		},
	}
}

func hasKubewardenLabel(labels map[string]string) bool {
	// Pre v1.16.0
	kubewardenLabel := labels["kubewarden"]
	// From v1.16.0 on we are using the recommended label "app.kubernetes.io/part-of"
	partOfLabel := labels[constants.PartOfLabelKey]

	return kubewardenLabel == "true" || partOfLabel == constants.PartOfLabelValue
}

func hasGroupAnnotation(annotations map[string]string) bool {
	return annotations[constants.WebhookConfigurationPolicyGroupAnnotationKey] == "true"
}

func getPolicyMapFromConfigMap(configMap *corev1.ConfigMap) (policyConfigEntryMap, error) {
	policyMap := policyConfigEntryMap{}
	if policies, ok := configMap.Data[constants.PolicyServerConfigPoliciesEntry]; ok {
		if err := json.Unmarshal([]byte(policies), &policyMap); err != nil {
			return policyMap, errors.Join(errors.New("failed to unmarshal policy mapping"), err)
		}
	} else {
		return policyMap, nil
	}
	return policyMap, nil
}

func setPolicyAsActive(policy policiesv1.Policy) {
	policy.SetStatus(policiesv1.PolicyStatusActive)
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyActive),
			Status:  metav1.ConditionTrue,
			Reason:  "PolicyActive",
			Message: "The policy webhook has been created",
		},
	)
}

func setPolicyConfigurationCondition(policyServerConfigMap *corev1.ConfigMap, policyServerDeployment *appsv1.Deployment, conditions *[]metav1.Condition) {
	if configAnnotation, ok := policyServerDeployment.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation]; ok {
		if configAnnotation == policyServerConfigMap.ResourceVersion {
			apimeta.SetStatusCondition(
				conditions,
				metav1.Condition{
					Type:    string(policiesv1.PolicyServerConfigurationUpToDate),
					Status:  metav1.ConditionTrue,
					Reason:  "ConfigurationVersionMatch",
					Message: "Configuration for this policy is up to date",
				},
			)
		} else {
			apimeta.SetStatusCondition(
				conditions,
				metav1.Condition{
					Type:    string(policiesv1.PolicyServerConfigurationUpToDate),
					Status:  metav1.ConditionFalse,
					Reason:  "ConfigurationVersionMismatch",
					Message: "Configuration for this policy is not up to date",
				},
			)
		}
	} else {
		apimeta.SetStatusCondition(
			conditions,
			metav1.Condition{
				Type:    string(policiesv1.PolicyServerConfigurationUpToDate),
				Status:  metav1.ConditionFalse,
				Reason:  "UnknownConfigurationVersion",
				Message: fmt.Sprintf("Configuration version annotation (%s) in deployment %s is missing", constants.PolicyServerDeploymentConfigVersionAnnotation, policyServerDeployment.GetName()),
			},
		)
	}
}
