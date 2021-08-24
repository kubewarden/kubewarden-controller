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

package policies

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/pkg/errors"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"time"
)

// PolicyServerReconciler reconciles a PolicyServer object
type PolicyServerReconciler struct {
	client.Client
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Reconciler admission.Reconciler
}

//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=policyservers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=policyservers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=policyservers/finalizers,verbs=update

func (r *PolicyServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("policyserver", req.NamespacedName)

	admissionReconciler := r.Reconciler
	admissionReconciler.Log = log

	var policyServer policiesv1alpha2.PolicyServer
	if err := r.Get(ctx, req.NamespacedName, &policyServer); err != nil {
		if apierrors.IsNotFound(err) {
			policyServer = policiesv1alpha2.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
			}
			log.Info("attempting delete")

			return ctrl.Result{}, admissionReconciler.ReconcileDeletion(ctx, &policyServer)
		}
		return ctrl.Result{}, fmt.Errorf("cannot retrieve admission policy: %w", err)
	}

	// Reconcile
	if err := admissionReconciler.Reconcile(ctx, &policyServer); err != nil {
		if admission.IsPolicyServerNotReady(err) {
			log.Info("delaying policy registration since policy server is not yet ready")
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Second * 5,
			}, nil
		}
		return ctrl.Result{}, fmt.Errorf("reconciliation error: %w", err)
	}
	if err := r.updatePolicyServerStatus(ctx, &policyServer); err != nil {
		return ctrl.Result{}, fmt.Errorf("update policy server status error: %w", err)
	}

	return ctrl.Result{}, nil

}

func (r *PolicyServerReconciler) updatePolicyServerStatus(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
) error {
	return errors.Wrapf(
		r.Client.Status().Update(ctx, policyServer),
		"failed to update ClusterAdmissionPolicy %q status", &policyServer.ObjectMeta,
	)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(context.Background(), &policiesv1alpha2.ClusterAdmissionPolicy{}, constants.PolicyServerIndexKey, func(object client.Object) []string {
		clusterAdmissionPolicy := object.(*policiesv1alpha2.ClusterAdmissionPolicy)
		return []string{clusterAdmissionPolicy.Spec.PolicyServer}
	})
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1alpha2.PolicyServer{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(&source.Kind{Type: &policiesv1alpha2.ClusterAdmissionPolicy{}}, handler.EnqueueRequestsFromMapFunc(func(object client.Object) []reconcile.Request {
			policy, ok := object.(*policiesv1alpha2.ClusterAdmissionPolicy)
			if !ok {
				return []ctrl.Request{}
			}
			// TODO check policy if server exist. use owner references or webhook for validating
			var originalPolicy policiesv1alpha2.ClusterAdmissionPolicy
			err := r.Client.Get(context.Background(), client.ObjectKey{
				Name: policy.Name,
			}, &originalPolicy)
			if apierrors.IsNotFound(err) {
				r.deleteWebhooks(policy)
			}
			return []ctrl.Request{
				{
					NamespacedName: client.ObjectKey{
						Name:      policy.Spec.PolicyServer,
						Namespace: policy.Namespace,
					},
				},
			}

		})).
		Complete(r)
}

func (r *PolicyServerReconciler) deleteWebhooks(policy *policiesv1alpha2.ClusterAdmissionPolicy) {
	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.Name,
		},
	}
	_ = r.Client.Delete(context.Background(), validatingWebhook)
	mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.Name,
		},
	}
	_ = r.Client.Delete(context.Background(), mutatingWebhook)
}
