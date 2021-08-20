package admission

import (
	"context"
	"encoding/json"
	"fmt"
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
	clusterAdminPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
) error {

	cfg := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, cfg)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return r.createPolicyServerConfigMap(ctx, policyServer, clusterAdminPolicies)
		}
		return fmt.Errorf("cannot lookup policies ConfigMap: %w", err)
	}

	newPoliciesYML, err := r.createPoliciesYML(clusterAdminPolicies)
	if err != nil {
		return fmt.Errorf("cannot create policies: %w", err)
	}
	currentPoliciesYML := cfg.Data[constants.PolicyServerConfigPoliciesEntry]

	if currentPoliciesYML != newPoliciesYML {
		patch := cfg.DeepCopy()
		patch.Data[constants.PolicyServerConfigPoliciesEntry] = newPoliciesYML
		err = r.Client.Patch(ctx, patch, client.MergeFrom(cfg))
		if err != nil {
			return fmt.Errorf("cannot patching policies: %w", err)
		}
	}
	return nil
}

func (r *Reconciler) createPolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
	clusterAdminPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
) error {
	policiesYML, err := r.createPoliciesYML(clusterAdminPolicies)
	if err != nil {
		return fmt.Errorf("cannot create policies: %w", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: policiesYML,
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

func (r *Reconciler) createPoliciesYML(clusterAdminPolicies *policiesv1alpha2.ClusterAdmissionPolicyList) (string, error) {
	policies := make(map[string]policyServerConfigEntry)

	for _, clusterAdmissionPolicy := range clusterAdminPolicies.Items {
		policies[clusterAdmissionPolicy.Name] = policyServerConfigEntry{
			URL:      clusterAdmissionPolicy.Spec.Module,
			Settings: clusterAdmissionPolicy.Spec.Settings,
		}
	}
	policiesYML, err := json.Marshal(policies)
	if err != nil {
		return "", fmt.Errorf("cannot marshal policies: %w", err)
	}

	return string(policiesYML), nil
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
