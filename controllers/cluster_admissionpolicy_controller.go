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
	"fmt"
	"time"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubewardenv1alpha1 "github.com/kubewarden/kubewarden-controller/api/v1alpha1"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
)

// ClusterAdmissionPolicyReconciler reconciles a
// ClusterAdmissionPolicy object
type ClusterAdmissionPolicyReconciler struct {
	client.Client
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	DeploymentsNamespace string
}

// +kubebuilder:rbac:groups=kubewarden.suse.com,resources=clusteradmissionpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubewarden.suse.com,resources=clusteradmissionpolicies/status,verbs=get;update;patch

// Reconcile takes care of reconciling ClusterAdmissionPolicy resources
func (r *ClusterAdmissionPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("clusteradmissionpolicy", req.NamespacedName)

	admissionReconciler := admission.Reconciler{
		Client:               r,
		DeploymentsNamespace: r.DeploymentsNamespace,
		Log:                  log,
	}

	var clusterAdmissionPolicy kubewardenv1alpha1.ClusterAdmissionPolicy
	if err := r.Get(ctx, req.NamespacedName, &clusterAdmissionPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			clusterAdmissionPolicy = kubewardenv1alpha1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
			}
			log.Info("Attempting delete", "policy", clusterAdmissionPolicy)
			return ctrl.Result{}, admissionReconciler.ReconcileDeletion(ctx, &clusterAdmissionPolicy)
		}
		return ctrl.Result{}, fmt.Errorf("cannot retrieve admission policy: %w", err)
	}

	// Reconcile
	err := admissionReconciler.Reconcile(ctx, &clusterAdmissionPolicy)
	if err == nil {
		return ctrl.Result{}, nil
	}

	if admission.IsPolicyServerNotReady(err) {
		log.Info("clusteradmissionpolicy", "Policy server not yet ready", err.Error())
		log.Info("clusteradmissionpolicy", "Delaying policy registration", req.Name)
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: time.Second * 5,
		}, nil
	}

	return ctrl.Result{}, fmt.Errorf("reconciliation error: %w", err)
}

// SetupWithManager takes care of setting up the resources to watch
func (r *ClusterAdmissionPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kubewardenv1alpha1.ClusterAdmissionPolicy{}).
		Complete(r)
}
