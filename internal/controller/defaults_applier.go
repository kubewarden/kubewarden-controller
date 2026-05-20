package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// DefaultsApplierReconciler watches a ConfigMap containing default Kubewarden
// resources (PolicyServer, ClusterAdmissionPolicy, etc.) and applies them to
// the cluster. It injects ownership labels and cleans up stale managed resources.

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch,namespace=kubewarden
// +kubebuilder:rbac:groups=policies.kubewarden.io,resources=policyservers;clusteradmissionpolicies;admissionpolicies;clusteradmissionpolicygroups;admissionpolicygroups,verbs=get;list;watch;create;update;patch;delete
type DefaultsApplierReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	Log                  logr.Logger
	DeploymentsNamespace string
	ConfigMapName        string
}

// Reconcile watches the defaults ConfigMap and applies the resources it contains.
func (r *DefaultsApplierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("configmap", req.NamespacedName)

	// Phase 1: Read ConfigMap
	var cm corev1.ConfigMap
	if err := r.Get(ctx, req.NamespacedName, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ConfigMap not found, cleaning up all managed resources")
			if cleanupErr := r.cleanupAll(ctx); cleanupErr != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup all managed resources: %w", cleanupErr)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get ConfigMap: %w", err)
	}

	// Phase 2: Apply desired resources
	decoder := serializer.NewCodecFactory(r.Scheme).UniversalDeserializer()
	desired := make(map[resourceKey]bool)

	for key, yamlData := range cm.Data {
		if len(key) < 5 || key[len(key)-5:] != ".yaml" {
			// Skip non-YAML keys
			continue
		}

		obj, gvk, err := decoder.Decode([]byte(yamlData), nil, nil)
		if err != nil {
			log.Error(err, "failed to decode resource from ConfigMap", "key", key)
			// Don't fail the whole reconciliation for one bad entry
			continue
		}

		clientObj, ok := obj.(client.Object)
		if !ok {
			log.Error(errors.New("decoded object is not a client.Object"), "skipping resource", "key", key, "gvk", gvk)
			continue
		}

		// Track this resource as desired
		rk := resourceKey{
			gvk:       gvk.String(),
			name:      clientObj.GetName(),
			namespace: clientObj.GetNamespace(),
		}
		desired[rk] = true

		// Apply the resource with ownership label injected
		if applyErr := r.applyResource(ctx, clientObj); applyErr != nil {
			return ctrl.Result{}, fmt.Errorf("failed to apply resource %s: %w", rk, applyErr)
		}
	}

	// Phase 3: Clean up stale managed resources
	if err := r.cleanupStale(ctx, desired); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup stale resources: %w", err)
	}

	log.Info("Reconciliation complete", "appliedResources", len(desired))
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *DefaultsApplierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(object client.Object) bool {
			return object.GetName() == r.ConfigMapName &&
				object.GetNamespace() == r.DeploymentsNamespace
		})).
		Complete(r); err != nil {
		return fmt.Errorf("failed to create DefaultsApplier controller: %w", err)
	}
	return nil
}

// applyResource creates or updates the resource, always injecting the ownership label.
func (r *DefaultsApplierReconciler) applyResource(ctx context.Context, desired client.Object) error {
	log := r.Log.WithValues("resource", client.ObjectKeyFromObject(desired), "kind", desired.GetObjectKind().GroupVersionKind().Kind)

	// CreateOrPatch GETs the existing object into desired, overwriting the
	// decoded state. Save a copy so the mutate function can restore the spec.
	desiredCopy, ok := desired.DeepCopyObject().(client.Object)
	if !ok {
		return errors.New("failed to cast deep copied object to client.Object")
	}

	_, err := controllerutil.CreateOrPatch(ctx, r.Client, desired, func() error {
		// Restore the spec from the decoded YAML
		copySpec(desiredCopy, desired)

		// Inject the ownership label
		labels := desired.GetLabels()
		if labels == nil {
			labels = make(map[string]string)
		}
		labels[constants.DefaultsManagedByLabelKey] = constants.DefaultsManagedByLabelValue
		desired.SetLabels(labels)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or patch resource: %w", err)
	}

	log.V(1).Info("Resource applied successfully")
	return nil
}

// copySpec copies the Spec field from src to dst for all supported resource types.
func copySpec(src, dst client.Object) {
	switch d := dst.(type) {
	case *policiesv1.PolicyServer:
		if s, ok := src.(*policiesv1.PolicyServer); ok {
			d.Spec = s.Spec
		}
	case *policiesv1.ClusterAdmissionPolicy:
		if s, ok := src.(*policiesv1.ClusterAdmissionPolicy); ok {
			d.Spec = s.Spec
		}
	case *policiesv1.AdmissionPolicy:
		if s, ok := src.(*policiesv1.AdmissionPolicy); ok {
			d.Spec = s.Spec
		}
	case *policiesv1.ClusterAdmissionPolicyGroup:
		if s, ok := src.(*policiesv1.ClusterAdmissionPolicyGroup); ok {
			d.Spec = s.Spec
		}
	case *policiesv1.AdmissionPolicyGroup:
		if s, ok := src.(*policiesv1.AdmissionPolicyGroup); ok {
			d.Spec = s.Spec
		}
	}
}

// cleanupStale removes managed resources that are not in the desired set.
func (r *DefaultsApplierReconciler) cleanupStale(ctx context.Context, desired map[resourceKey]bool) error {
	managedSelector := client.MatchingLabels{
		constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue,
	}

	// List all managed resource types
	resourceLists := []client.ObjectList{
		&policiesv1.PolicyServerList{},
		&policiesv1.ClusterAdmissionPolicyList{},
		&policiesv1.AdmissionPolicyList{},
		&policiesv1.ClusterAdmissionPolicyGroupList{},
		&policiesv1.AdmissionPolicyGroupList{},
	}

	for _, list := range resourceLists {
		if err := r.List(ctx, list, managedSelector); err != nil {
			return fmt.Errorf("failed to list managed resources: %w", err)
		}

		items, err := extractItems(list)
		if err != nil {
			return err
		}

		for _, item := range items {
			rk := resourceKey{
				gvk:       item.GetObjectKind().GroupVersionKind().String(),
				name:      item.GetName(),
				namespace: item.GetNamespace(),
			}

			if !desired[rk] {
				r.Log.Info("Deleting stale managed resource", "resource", rk)
				if deleteErr := r.Delete(ctx, item); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
					return fmt.Errorf("failed to delete stale resource %s: %w", rk, deleteErr)
				}
			}
		}
	}

	return nil
}

// cleanupAll removes all managed resources (called when ConfigMap is absent).
func (r *DefaultsApplierReconciler) cleanupAll(ctx context.Context) error {
	return r.cleanupStale(ctx, make(map[resourceKey]bool))
}

// resourceKey uniquely identifies a Kubernetes resource.
type resourceKey struct {
	gvk       string
	name      string
	namespace string
}

func (rk resourceKey) String() string {
	if rk.namespace == "" {
		return fmt.Sprintf("%s/%s", rk.gvk, rk.name)
	}
	return fmt.Sprintf("%s/%s/%s", rk.gvk, rk.namespace, rk.name)
}

// extractItems extracts client.Objects from a typed list.
func extractItems(list client.ObjectList) ([]client.Object, error) {
	switch v := list.(type) {
	case *policiesv1.PolicyServerList:
		items := make([]client.Object, len(v.Items))
		for i := range v.Items {
			items[i] = &v.Items[i]
		}
		return items, nil
	case *policiesv1.ClusterAdmissionPolicyList:
		items := make([]client.Object, len(v.Items))
		for i := range v.Items {
			items[i] = &v.Items[i]
		}
		return items, nil
	case *policiesv1.AdmissionPolicyList:
		items := make([]client.Object, len(v.Items))
		for i := range v.Items {
			items[i] = &v.Items[i]
		}
		return items, nil
	case *policiesv1.ClusterAdmissionPolicyGroupList:
		items := make([]client.Object, len(v.Items))
		for i := range v.Items {
			items[i] = &v.Items[i]
		}
		return items, nil
	case *policiesv1.AdmissionPolicyGroupList:
		items := make([]client.Object, len(v.Items))
		for i := range v.Items {
			items[i] = &v.Items[i]
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unknown list type: %T", list)
	}
}
