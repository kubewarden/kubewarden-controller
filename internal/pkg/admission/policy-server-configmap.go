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

type policyServerSourcesEntry struct {
	// nolint:tagliatelle
	InsecureSources []string `json:"insecure_sources,omitempty"`
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
		return fmt.Errorf("cannot lookup policy server ConfigMap: %w", err)
	}

	return r.updateIfNeeded(ctx, cfg, clusterAdmissionPolicies, policyServer)
}

func (r *Reconciler) updateIfNeeded(ctx context.Context, cfg *corev1.ConfigMap,
	clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
	policyServer *policiesv1alpha2.PolicyServer) error {
	newPoliciesMap := r.createPoliciesMap(clusterAdmissionPolicies)

	var (
		shouldUpdatePolicies, shouldUpdateSources bool
		err                                       error
	)
	if shouldUpdatePolicies, err = shouldUpdatePolicyMap(cfg.Data[constants.PolicyServerConfigPoliciesEntry], newPoliciesMap); err != nil {
		return fmt.Errorf("cannot compare policies: %w", err)
	}
	if shouldUpdateSources, err = shouldUpdateSourcesMap(cfg.Data[constants.PolicyServerConfigSourcesEntry], policyServer.Spec.InsecureSources); err != nil {
		return fmt.Errorf("cannot compare insecureSources: %w", err)
	}
	if !(shouldUpdatePolicies || shouldUpdateSources) {
		return nil
	}

	patch := cfg.DeepCopy()
	if shouldUpdatePolicies {
		newPoliciesYML, err := json.Marshal(newPoliciesMap)
		if err != nil {
			return fmt.Errorf("cannot marshal policies: %w", err)
		}
		patch.Data[constants.PolicyServerConfigPoliciesEntry] = string(newPoliciesYML)
	}
	if shouldUpdateSources {
		newSources := r.createSourcesMap(policyServer.Spec.InsecureSources)
		newSourcesYML, err := json.Marshal(newSources)
		if err != nil {
			return fmt.Errorf("cannot marshal insecureSources: %w", err)
		}
		patch.Data[constants.PolicyServerConfigSourcesEntry] = string(newSourcesYML)
	}
	err = r.Client.Patch(ctx, patch, client.MergeFrom(cfg))
	if err != nil {
		return fmt.Errorf("cannot patch PolicyServer Configmap: %w", err)
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

func shouldUpdateSourcesMap(currentSourcesYML string, newInsecureSourcesList []string) (bool, error) {
	var currentSources policyServerSourcesEntry

	if err := json.Unmarshal([]byte(currentSourcesYML), &currentSources); err != nil {
		return false, fmt.Errorf("cannot unmarshal insecureSources: %w", err)
	}

	return !reflect.DeepEqual(currentSources.InsecureSources, newInsecureSourcesList), nil
}

func (r *Reconciler) createPolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
	clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
) error {
	policies := r.createPoliciesMap(clusterAdmissionPolicies)
	sources := r.createSourcesMap(policyServer.Spec.InsecureSources)

	policiesYML, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("cannot marshal policies: %w", err)
	}
	sourcesYML, err := json.Marshal(sources)
	if err != nil {
		return fmt.Errorf("cannot marshal insecureSources: %w", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: string(policiesYML),
		constants.PolicyServerConfigSourcesEntry:  string(sourcesYML),
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

func (r *Reconciler) createPoliciesMap(clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList) map[string]policyServerConfigEntry {
	policies := make(map[string]policyServerConfigEntry)

	for _, clusterAdmissionPolicy := range clusterAdmissionPolicies.Items {
		policies[clusterAdmissionPolicy.Name] = policyServerConfigEntry{
			URL:      clusterAdmissionPolicy.Spec.Module,
			Settings: clusterAdmissionPolicy.Spec.Settings,
		}
	}
	return policies
}

func (r *Reconciler) createSourcesMap(sourcesList []string) policyServerSourcesEntry {
	if sourcesList == nil {
		sourcesList = make([]string, 0)
	}
	return policyServerSourcesEntry{
		InsecureSources: sourcesList,
	}
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
