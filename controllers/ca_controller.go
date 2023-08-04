/*
Copyright 2023.

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

	"github.com/go-logr/logr"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// This controller reconcile the root ca used by the Kubewarden stack
type KubewardenCAReconciler struct {
	client.Client
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Reconciler admission.Reconciler
}

func (r *KubewardenCAReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	CASecret, initialized, err := r.Reconciler.FetchOrInitializeRootCASecret(ctx, admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "failed to create root CA")
	}
	// if we have a new kubewarden root ca it is necessary to update the policy server secrets.
	if initialized {
		r.Log.Info("Root CA initialized")
		err := r.Reconciler.UpdateAllPolicyServerSecrets(ctx, CASecret)
		if err != nil {
			return ctrl.Result{}, errors.Wrap(err, "failed to recreate policy servers secrets")
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KubewardenCAReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Watches(&source.Kind{Type: &corev1.Secret{}}, handler.EnqueueRequestsFromMapFunc(func(object client.Object) []reconcile.Request {
			// CA controller watches only root ca secret.
			// policy server secret should be managed by the policy server controller
			secret, ok := object.(*corev1.Secret)
			if !ok {
				r.Log.Info("object is not type of corev1.Secret: %+v", secret)
				return []ctrl.Request{}
			}
			if secret.Name == constants.KubewardenCARootSecretName {
				return []ctrl.Request{
					{
						NamespacedName: client.ObjectKey{
							Name: secret.Name,
						},
					},
				}
			}
			return []ctrl.Request{}
		})).Complete(r)
	return errors.Wrap(err, "failed enrolling controller with manager")
}
