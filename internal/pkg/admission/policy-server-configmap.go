package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	policiesv1 "github.com/kubewarden/kubewarden-controller/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type PolicyServerConfigEntry struct {
	NamespacedName  types.NamespacedName `json:"namespacedName"`
	URL             string               `json:"url"`
	PolicyMode      string               `json:"policyMode"`
	AllowedToMutate bool                 `json:"allowedToMutate"`
	Settings        runtime.RawExtension `json:"settings,omitempty"`
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
	policyServer *policiesv1.PolicyServer,
	policies []policiesv1.Policy,
) error {
	cfg := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, cfg)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return r.createPolicyServerConfigMap(ctx, policyServer, policies)
		}
		return fmt.Errorf("cannot lookup Policy server ConfigMap: %w", err)
	}

	return r.updateIfNeeded(ctx, cfg, policies, policyServer)
}

func (r *Reconciler) updateIfNeeded(ctx context.Context, cfg *corev1.ConfigMap,
	policies []policiesv1.Policy,
	policyServer *policiesv1.PolicyServer) error {
	newPoliciesMap := r.createPoliciesMap(policies)
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

func shouldUpdatePolicyMap(currentPoliciesYML string, newPoliciesMap PolicyConfigEntryMap) (bool, error) {
	var currentPoliciesMap PolicyConfigEntryMap

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
	policyServer *policiesv1.PolicyServer,
	policies []policiesv1.Policy,
) error {
	policiesMap := r.createPoliciesMap(policies)
	policiesYML, err := json.Marshal(policiesMap)
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
			Labels: map[string]string{
				constants.PolicyServerLabelKey: policyServer.ObjectMeta.Name,
			},
		},
		Data: data,
	}

	//nolint:wrapcheck
	return r.Client.Create(ctx, cfg)
}

type PolicyConfigEntryMap map[string]PolicyServerConfigEntry

func (policyConfigEntryMap PolicyConfigEntryMap) ToAdmissionPolicyReconcileRequests() []reconcile.Request {
	res := []reconcile.Request{}
	for _, policy := range policyConfigEntryMap {
		if policy.NamespacedName.Namespace == "" {
			continue
		}
		res = append(res, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: policy.NamespacedName.Namespace,
				Name:      policy.NamespacedName.Name,
			},
		})
	}
	return res
}

func (policyConfigEntryMap PolicyConfigEntryMap) ToClusterAdmissionPolicyReconcileRequests() []reconcile.Request {
	res := []reconcile.Request{}
	for _, policy := range policyConfigEntryMap {
		if policy.NamespacedName.Namespace != "" {
			continue
		}
		res = append(res, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: policy.NamespacedName.Name,
			},
		})
	}
	return res
}

func (r *Reconciler) createPoliciesMap(admissionPolicies []policiesv1.Policy) PolicyConfigEntryMap {
	policies := PolicyConfigEntryMap{}
	for _, admissionPolicy := range admissionPolicies {
		policies[admissionPolicy.GetUniqueName()] = PolicyServerConfigEntry{
			NamespacedName: types.NamespacedName{
				Namespace: admissionPolicy.GetNamespace(),
				Name:      admissionPolicy.GetName(),
			},
			URL:             admissionPolicy.GetModule(),
			PolicyMode:      string(admissionPolicy.GetPolicyMode()),
			AllowedToMutate: admissionPolicy.IsMutating(),
			Settings:        admissionPolicy.GetSettings(),
		}
	}
	return policies
}

func (r *Reconciler) createSourcesMap(policyServer *policiesv1.PolicyServer) policyServerSourcesEntry {
	sourcesEntry := policyServerSourcesEntry{}
	sourcesEntry.InsecureSources = policyServer.Spec.InsecureSources
	if sourcesEntry.InsecureSources == nil {
		sourcesEntry.InsecureSources = make([]string, 0)
	}

	sourcesEntry.SourceAuthorities = make(map[string][]policyServerSourceAuthority)
	// build sources.yml with data keys for Policy-server
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

func (r *Reconciler) policyServerConfigMapVersion(ctx context.Context, policyServer *policiesv1.PolicyServer) (string, error) {
	// By using Unstructured data we force the client to fetch fresh, uncached
	// data from the API server
	unstructuredObj := &unstructured.Unstructured{}
	unstructuredObj.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	})
	err := r.APIReader.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, unstructuredObj)

	if err != nil {
		return "", fmt.Errorf("cannot retrieve existing policies ConfigMap: %w", err)
	}

	return unstructuredObj.GetResourceVersion(), nil
}
