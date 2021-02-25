/*


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
	"time"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chimerav1alpha1 "github.com/chimera-kube/chimera-controller/api/v1alpha1"

	"github.com/chimera-kube/chimera-controller/internal/pkg/admission"
)

// AdmissionPolicyReconciler reconciles a AdmissionPolicy object
type AdmissionPolicyReconciler struct {
	client.Client
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	DeploymentsNamespace string
}

// +kubebuilder:rbac:groups=chimera.suse.com,resources=admissionpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=chimera.suse.com,resources=admissionpolicies/status,verbs=get;update;patch

func (r *AdmissionPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("admissionpolicy", req.NamespacedName)

	admissionReconciler := admission.AdmissionReconciler{
		Client:               r,
		DeploymentsNamespace: r.DeploymentsNamespace,
		Log:                  log,
	}

	var admissionPolicy chimerav1alpha1.AdmissionPolicy
	if err := r.Get(ctx, req.NamespacedName, &admissionPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			admissionPolicy = chimerav1alpha1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
			}
			log.Info("Attempting delete", "policy", admissionPolicy)
			return ctrl.Result{}, admissionReconciler.ReconcileDeletion(ctx, &admissionPolicy)
		}
		log.Error(err, "Could not retrieve admission policy")
		return ctrl.Result{}, err
	}

	// Reconcile
	err := admissionReconciler.Reconcile(ctx, &admissionPolicy)
	if err == nil {
		return ctrl.Result{}, nil
	}

	if admission.IsPolicyServerNotReady(err) {
		log.Info("admissionpolicy", "Policy server not yet ready", err.Error())
		log.Info("admissionpolicy", "Delaying policy registration", req.Name)
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: time.Second * 5,
		}, nil
	}

	return ctrl.Result{}, err
}

func (r *AdmissionPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&chimerav1alpha1.AdmissionPolicy{}).
		Complete(r)
}
