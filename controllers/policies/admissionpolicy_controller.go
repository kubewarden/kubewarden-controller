package policies

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admission"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/naming"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=admissionpolicies,verbs=get;list;watch;delete
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=admissionpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=admissionpolicies/finalizers,verbs=update

// AdmissionPolicyReconciler reconciles an AdmissionPolicy object
type AdmissionPolicyReconciler struct {
	client.Client
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Reconciler admission.Reconciler
}

// Reconcile reconciles admission policies
func (r *AdmissionPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var admissionPolicy policiesv1alpha2.AdmissionPolicy
	if err := r.Reconciler.APIReader.Get(ctx, req.NamespacedName, &admissionPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("cannot retrieve admission policy: %w", err)
	}

	if admissionPolicy.DeletionTimestamp != nil {
		return reconcilePolicyDeletion(ctx, r.Client, &admissionPolicy)
	}

	return reconcilePolicy(ctx, r.Client, r.Reconciler, &admissionPolicy)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AdmissionPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1alpha2.AdmissionPolicy{}).
		Watches(
			&source.Kind{Type: &corev1.ConfigMap{}},
			handler.EnqueueRequestsFromMapFunc(r.findAdmissionPoliciesForConfigMap),
		).
		Watches(
			&source.Kind{Type: &corev1.Pod{}},
			handler.EnqueueRequestsFromMapFunc(r.findAdmissionPoliciesForPod),
		).
		Complete(r)

	return errors.Wrap(err, "failed enrolling controller with manager")
}

func (r *AdmissionPolicyReconciler) findAdmissionPoliciesForConfigMap(object client.Object) []reconcile.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return []reconcile.Request{}
	}
	if _, isKubewardenConfigmap := configMap.Labels[constants.PolicyServerLabelKey]; !isKubewardenConfigmap {
		return []reconcile.Request{}
	}
	res := []reconcile.Request{}
	policyMap, err := getPolicyMapFromConfigMap(configMap)
	if err != nil {
		return res
	}
	return policyMap.ToAdmissionPolicyReconcileRequests()
}

func (r *AdmissionPolicyReconciler) findAdmissionPoliciesForPod(object client.Object) []reconcile.Request {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerName, isKubewardenPod := pod.Labels[constants.PolicyServerLabelKey]
	if !isKubewardenPod {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := naming.PolicyServerDeploymentNameForPolicyServerName(policyServerName)
	configMap := corev1.ConfigMap{}
	err := r.Reconciler.APIReader.Get(context.TODO(), client.ObjectKey{
		Namespace: pod.ObjectMeta.Namespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return r.findAdmissionPoliciesForConfigMap(&configMap)
}
