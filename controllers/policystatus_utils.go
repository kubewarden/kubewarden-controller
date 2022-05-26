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
	"encoding/json"
	"fmt"

	v1alpha2 "github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func getPolicyMapFromConfigMap(configMap *corev1.ConfigMap) (admission.PolicyConfigEntryMap, error) {
	policyMap := admission.PolicyConfigEntryMap{}
	if policies, ok := configMap.Data[constants.PolicyServerConfigPoliciesEntry]; ok {
		if err := json.Unmarshal([]byte(policies), &policyMap); err != nil {
			return policyMap, errors.Wrap(err, "failed to unmarshal policy mapping")
		}
	} else {
		return policyMap, nil
	}
	return policyMap, nil
}

func SetPolicyConfigurationCondition(policyServerConfigMap *corev1.ConfigMap, policyServerDeployment *appsv1.Deployment, conditions *[]metav1.Condition) {
	if configAnnotation, ok := policyServerDeployment.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation]; ok {
		if configAnnotation == policyServerConfigMap.ResourceVersion {
			apimeta.SetStatusCondition(
				conditions,
				metav1.Condition{
					Type:    string(v1alpha2.PolicyServerConfigurationUpToDate),
					Status:  metav1.ConditionTrue,
					Reason:  "ConfigurationVersionMatch",
					Message: "Configuration for this policy is up to date",
				},
			)
		} else {
			apimeta.SetStatusCondition(
				conditions,
				metav1.Condition{
					Type:    string(v1alpha2.PolicyServerConfigurationUpToDate),
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
				Type:    string(v1alpha2.PolicyServerConfigurationUpToDate),
				Status:  metav1.ConditionFalse,
				Reason:  "UnknownConfigurationVersion",
				Message: fmt.Sprintf("Configuration version annotation (%s) in deployment %s is missing", constants.PolicyServerDeploymentConfigVersionAnnotation, policyServerDeployment.GetName()),
			},
		)
	}
}

func isLatestReplicaSetFromPolicyServerDeployment(replicaSet *appsv1.ReplicaSet, policyServerDeployment *appsv1.Deployment, configMapVersion string) bool {
	return replicaSet.Annotations[constants.KubernetesRevisionAnnotation] == policyServerDeployment.Annotations[constants.KubernetesRevisionAnnotation] &&
		replicaSet.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] == configMapVersion
}

func isPolicyUniquelyReachable(ctx context.Context, apiReader client.Reader, policyServerDeployment *appsv1.Deployment, policyName string) bool {
	configMap := corev1.ConfigMap{}

	err := apiReader.Get(ctx, client.ObjectKey{
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
	if err := apiReader.List(ctx, &replicaSets, client.MatchingLabels{constants.PolicyServerLabelKey: policyServerDeployment.Labels[constants.PolicyServerLabelKey]}); err != nil {
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
	if err := apiReader.List(ctx, &pods, client.MatchingLabels{constants.PolicyServerLabelKey: policyServerDeployment.Labels[constants.PolicyServerLabelKey]}); err != nil {
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
