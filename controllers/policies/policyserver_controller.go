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
	"time"

	"github.com/go-logr/logr"
	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
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
//
// The following ought to be part of kubewarden-controller-manager-cluster-role:
//+kubebuilder:rbac:groups=core,resources=secrets;configmaps,verbs=list;watch
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=list;watch
//
// The following ought to be part of kubewarden-controller-manager-namespaced-role:
//+kubebuilder:rbac:groups=core,resources=secrets;services;configmaps,verbs=get;list;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;create;delete;update;patch

func (r *PolicyServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("policyserver", req.NamespacedName)

	admissionReconciler := r.Reconciler
	admissionReconciler.Log = log

	var policyServer policiesv1alpha2.PolicyServer
	if err := r.Get(ctx, req.NamespacedName, &policyServer); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("cannot retrieve policy server: %w", err)
	}

	if policyServer.ObjectMeta.DeletionTimestamp != nil {
		if hasPolicies, err := admissionReconciler.HasClusterAdmissionPoliciesBounded(ctx, &policyServer); hasPolicies {
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("cannot retrieve cluster admission policies: %w", err)
			}
			err := admissionReconciler.DeleteAllClusterAdmissionPolicies(ctx, &policyServer)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("cannot delete cluster admission policies: %w", err)
			}
			log.Info("delaying policy server deletion since all cluster admission policies are not deleted yet")
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Second * 5,
			}, nil
		}

		err := admissionReconciler.ReconcileDeletion(ctx, &policyServer)
		if err != nil {
			err = fmt.Errorf("failed reconciling deletion of policyServer %s: %w",
				policyServer.Name, err)
		}
		return ctrl.Result{}, err
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
		"failed to update PolicyServer %q status", &policyServer.ObjectMeta,
	)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(context.Background(), &policiesv1alpha2.ClusterAdmissionPolicy{}, constants.PolicyServerIndexKey, func(object client.Object) []string {
		policy, ok := object.(*policiesv1alpha2.ClusterAdmissionPolicy)
		if !ok {
			r.Log.Error(nil, "object is not type of ClusterAdmissionPolicy: %#v", policy)
			return []string{}
		}
		return []string{policy.Spec.PolicyServer}
	})
	if err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	err = mgr.GetFieldIndexer().IndexField(context.Background(), &policiesv1alpha2.PolicyServer{}, constants.PolicyServerIndexName, func(object client.Object) []string {
		policyServer, ok := object.(*policiesv1alpha2.PolicyServer)
		if !ok {
			r.Log.Error(nil, "object is not type of PolicyServer: %#v", policyServer)
			return []string{}
		}
		return []string{policyServer.Name}
	})
	if err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	err = ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1alpha2.PolicyServer{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(&source.Kind{Type: &policiesv1alpha2.ClusterAdmissionPolicy{}}, handler.EnqueueRequestsFromMapFunc(func(object client.Object) []reconcile.Request {
			policy, ok := object.(*policiesv1alpha2.ClusterAdmissionPolicy)
			if !ok {
				r.Log.Error(err, "object is not type of ClusterAdmissionPolicy: %#v", policy)
				return []ctrl.Request{}
			}

			if policy.Status.PolicyStatus == "" {
				policy.Status.PolicyStatus = policiesv1alpha2.ClusterAdmissionPolicyStatusUnscheduled
				err := r.Reconciler.UpdateAdmissionPolicyStatus(context.Background(), policy)
				if err != nil {
					r.Log.Error(err, "cannot update status of policy "+policy.Name)
					return []ctrl.Request{}
				}
			}

			var policyServers policiesv1alpha2.PolicyServerList
			err := r.List(context.Background(), &policyServers, client.MatchingFields{constants.PolicyServerIndexName: policy.Spec.PolicyServer})
			if err != nil {
				r.Log.Error(err, "cannot list PolicyServers corresponding to policy "+policy.Name)
				return []ctrl.Request{}
			}
			if len(policyServers.Items) == 0 {
				policy.Status.PolicyStatus = policiesv1alpha2.ClusterAdmissionPolicyStatusUnschedulable
				err := r.Reconciler.UpdateAdmissionPolicyStatus(context.Background(), policy)
				if err != nil {
					r.Log.Error(err, "cannot update status of policy "+policy.Name)
				}
				r.Log.Info("policy " + policy.Name + " cannot be scheduled: no matching PolicyServer")
				return []ctrl.Request{}
			}
			if policy.DeletionTimestamp != nil {
				// policy scheduled for deletion hence read-only, can't change
				// status:
				return []ctrl.Request{
					{
						NamespacedName: client.ObjectKey{
							Name: policy.Spec.PolicyServer,
						},
					},
				}
			}
			policy.Status.PolicyStatus = policiesv1alpha2.ClusterAdmissionPolicyStatusPending
			err = r.Reconciler.UpdateAdmissionPolicyStatus(context.Background(), policy)
			if err != nil {
				r.Log.Error(err, "cannot update status of policy "+policy.Name)
				return []ctrl.Request{}
			}
			r.Log.Info("policy " + policy.Name + " pending")
			return []ctrl.Request{
				{
					NamespacedName: client.ObjectKey{
						Name: policy.Spec.PolicyServer,
					},
				},
			}
		})).
		Complete(r)

	if err != nil {
		err = fmt.Errorf("failed enrolling controller with manager: %w", err)
	}
	return err
}
