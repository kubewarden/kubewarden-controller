/*
Copyright 2026.

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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NamespacedCacheOptions returns cache.Options that restrict LIST/WATCH for
// namespace-scoped resources the controller manages exclusively within
// deploymentsNamespace. Without this restriction, controller-runtime creates
// cluster-wide watches, which require privileges the production ServiceAccount
// does not have.
//
// Only resources the controller owns within a single namespace are listed here.
// Resources like AdmissionPolicy that the controller accesses across all
// namespaces must NOT be restricted, so they are intentionally omitted.
func NamespacedCacheOptions(deploymentsNamespace string) cache.Options {
	namespaceSelector := cache.ByObject{
		Field: fields.ParseSelectorOrDie("metadata.namespace=" + deploymentsNamespace),
	}
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&appsv1.ReplicaSet{}:                 namespaceSelector,
			&corev1.Secret{}:                     namespaceSelector,
			&corev1.Pod{}:                        namespaceSelector,
			&corev1.Service{}:                    namespaceSelector,
			&k8spoliciesv1.PodDisruptionBudget{}: namespaceSelector,
			&corev1.ConfigMap{}:                  namespaceSelector,
			&appsv1.Deployment{}:                 namespaceSelector,
		},
	}
}
