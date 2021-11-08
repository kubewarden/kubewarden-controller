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

type sourceAuthorityType string

const (
	Data sourceAuthorityType = "Data" // only data type is supported
)

type policyServerSourceAuthority struct {
	Type sourceAuthorityType `json:"type"`
	Data string              `json:"data"` // contains a PEM encoded certificate
}

// nolint:tagliatelle
type policyServerSourcesEntry struct {
	InsecureSources   []string                                 `json:"insecure_sources,omitempty"`
	SourceAuthorities map[string][]policyServerSourceAuthority `json:"source_authorities,omitempty"`
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
	newSourcesList := r.createSourcesMap(policyServer)

	var (
		shouldUpdatePolicies, shouldUpdateSources bool
		err                                       error
	)
	if shouldUpdatePolicies, err = shouldUpdatePolicyMap(cfg.Data[constants.PolicyServerConfigPoliciesEntry], newPoliciesMap); err != nil {
		return fmt.Errorf("cannot compare policies: %w", err)
	}
	if shouldUpdateSources, err = shouldUpdateSourcesList(cfg.Data[constants.PolicyServerConfigSourcesEntry],
		newSourcesList); err != nil {
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
		newSourcesYML, err := json.Marshal(newSourcesList)
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

func shouldUpdateSourcesList(currentSourcesYML string, newSources policyServerSourcesEntry) (bool, error) {
	var currentSources policyServerSourcesEntry
	if err := json.Unmarshal([]byte(currentSourcesYML), &currentSources); err != nil {
		return false, fmt.Errorf("cannot unmarshal insecureSources: %w", err)
	}

	return !reflect.DeepEqual(currentSources, newSources), nil
}

func (r *Reconciler) createPolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
	clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList,
) error {
	policies := r.createPoliciesMap(clusterAdmissionPolicies)
	policiesYML, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("cannot marshal policies: %w", err)
	}

	sources := r.createSourcesMap(policyServer)
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

func (r *Reconciler) createSourcesMap(policyServer *policiesv1alpha2.PolicyServer) (sourcesEntry policyServerSourcesEntry) {
	sourcesEntry.InsecureSources = policyServer.Spec.InsecureSources
	if sourcesEntry.InsecureSources == nil {
		sourcesEntry.InsecureSources = make([]string, 0)
	}

	sourcesEntry.SourceAuthorities = make(map[string][]policyServerSourceAuthority)
	// build sources.yml with data keys for policy-server
	for uri, certs := range policyServer.Spec.SourceAuthorities {
		sourcesEntry.SourceAuthorities[uri] = make([]policyServerSourceAuthority, 0)
		for _, cert := range certs {
			sourcesEntry.SourceAuthorities[uri] = append(sourcesEntry.SourceAuthorities[uri],
				policyServerSourceAuthority{
					Type: Data,
					Data: cert,
				})
		}
	}
	return sourcesEntry
}

func (r *Reconciler) policyServerConfigMapVersion(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) (string, error) {
	// By using Unstructured data we force the client to fetch fresh, uncached
	// data from the API server
	unstructuredObj := &unstructured.Unstructured{}
	unstructuredObj.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	})
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, unstructuredObj)

	if err != nil {
		return "", fmt.Errorf("cannot retrieve existing policies ConfigMap: %w", err)
	}

	return unstructuredObj.GetResourceVersion(), nil
}
