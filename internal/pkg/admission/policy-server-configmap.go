package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type policyServerConfigEntry struct {
	URL      string               `json:"url"`
	Settings runtime.RawExtension `json:"settings,omitempty"`
}

// Reconciles the ConfigMap that holds the configuration of the Policy Server
func (r *Reconciler) reconcilePolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
	clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
) error {
	cfg := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, cfg)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return r.createPolicyServerConfigMap(ctx, policyServer, clusterAdmissionPolicies)
		}
		return fmt.Errorf("cannot lookup policies ConfigMap: %w", err)
	}

	return r.updateIfNeeded(ctx, cfg, clusterAdmissionPolicies)
}

func (r *Reconciler) updateIfNeeded(ctx context.Context, cfg *corev1.ConfigMap, clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList) error {
	newPoliciesMap, err := r.createPoliciesMap(clusterAdmissionPolicies)
	if err != nil {
		return fmt.Errorf("cannot create policies: %w", err)
	}

	if shouldUpdate, err := shouldUpdatePolicyMap(cfg.Data[constants.PolicyServerConfigPoliciesEntry], newPoliciesMap); err != nil {
		return fmt.Errorf("cannot compare policies: %w", err)
	} else if shouldUpdate {
		newPoliciesYML, err := json.Marshal(newPoliciesMap)
		if err != nil {
			return fmt.Errorf("cannot marshal policies: %w", err)
		}
		patch := cfg.DeepCopy()
		patch.Data[constants.PolicyServerConfigPoliciesEntry] = string(newPoliciesYML)
		err = r.Client.Patch(ctx, patch, client.MergeFrom(cfg))
		if err != nil {
			return fmt.Errorf("cannot patching policies: %w", err)
		}
	}

	return nil
}

func shouldUpdatePolicyMap(currentPoliciesYML string, newPoliciesMap map[string]policyServerConfigEntry) (bool, error) {
	var currentPoliciesMap map[string]policyServerConfigEntry

	if err := json.Unmarshal([]byte(currentPoliciesYML), &currentPoliciesMap); err != nil {
		return false, fmt.Errorf("cannot unmarshal policies: %w", err)
	}

	return !reflect.DeepEqual(currentPoliciesMap, newPoliciesMap), nil
}

func (r *Reconciler) createPolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
	clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
) error {
	policies, err := r.createPoliciesMap(clusterAdmissionPolicies)
	if err != nil {
		return fmt.Errorf("cannot create policies: %w", err)
	}

	policiesYML, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("cannot marshal policies: %w", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: string(policiesYML),
	}

	cfg := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
		Data: data,
	}

	//nolint:wrapcheck
	return r.Client.Create(ctx, cfg)
}

func (r *Reconciler) createPoliciesMap(clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList) (map[string]policyServerConfigEntry, error) {
	policies := make(map[string]policyServerConfigEntry)

	for _, clusterAdmissionPolicy := range clusterAdmissionPolicies.Items {
		policies[clusterAdmissionPolicy.Name] = policyServerConfigEntry{
			URL:      clusterAdmissionPolicy.Spec.Module,
			Settings: clusterAdmissionPolicy.Spec.Settings,
		}
	}

	return policies, nil
}

func (r *Reconciler) policyServerConfigMapVersion(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) (string, error) {
	// By using Unstructured data we force the client to fetch fresh, uncached
	// data from the API server
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	})
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, u)

	if err != nil {
		return "", fmt.Errorf("cannot retrieve existing policies ConfigMap: %w", err)
	}

	return u.GetResourceVersion(), nil
}
