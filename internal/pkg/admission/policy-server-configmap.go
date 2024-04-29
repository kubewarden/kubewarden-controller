package admission

import (
	"context"
	"encoding/json"
	"fmt"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type PolicyServerConfigEntry struct {
	NamespacedName        types.NamespacedName              `json:"namespacedName"`
	URL                   string                            `json:"url"`
	PolicyMode            string                            `json:"policyMode"`
	AllowedToMutate       bool                              `json:"allowedToMutate"`
	ContextAwareResources []policiesv1.ContextAwareResource `json:"contextAwareResources,omitempty"`
	Settings              runtime.RawExtension              `json:"settings,omitempty"`
}

type sourceAuthorityType string

const (
	Data sourceAuthorityType = "Data" // only data type is supported
)

type policyServerSourceAuthority struct {
	Type sourceAuthorityType `json:"type"`
	Data string              `json:"data"` // contains a PEM encoded certificate
}

//nolint:tagliatelle
type PolicyServerSourcesEntry struct {
	InsecureSources   []string                                 `json:"insecure_sources,omitempty"`
	SourceAuthorities map[string][]policyServerSourceAuthority `json:"source_authorities,omitempty"`
}

// Reconciles the ConfigMap that holds the configuration of the Policy Server
func (r *Reconciler) reconcilePolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1.PolicyServer,
	policies []policiesv1.Policy,
) error {
	cfg := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cfg, func() error {
		return r.updateConfigMapData(cfg, policyServer, policies)
	})
	if err != nil {
		return fmt.Errorf("cannot create or update PolicyServer ConfigMap: %w", err)
	}
	return nil
}

// Function used to update the ConfigMap data when creating or updating it
func (r *Reconciler) updateConfigMapData(cfg *corev1.ConfigMap, policyServer *policiesv1.PolicyServer, policies []policiesv1.Policy) error {
	policiesMap := buildPoliciesMap(policies)
	policiesYML, err := json.Marshal(policiesMap)
	if err != nil {
		return fmt.Errorf("cannot marshal policies: %w", err)
	}

	sources := buildSourcesMap(policyServer)
	sourcesYML, err := json.Marshal(sources)
	if err != nil {
		return fmt.Errorf("cannot marshal insecureSources: %w", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: string(policiesYML),
		constants.PolicyServerConfigSourcesEntry:  string(sourcesYML),
	}

	cfg.Data = data
	cfg.ObjectMeta.Labels = map[string]string{
		constants.PolicyServerLabelKey: policyServer.ObjectMeta.Name,
	}
	return nil
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

func buildPoliciesMap(admissionPolicies []policiesv1.Policy) PolicyConfigEntryMap {
	policies := PolicyConfigEntryMap{}
	for _, admissionPolicy := range admissionPolicies {
		policies[admissionPolicy.GetUniqueName()] = PolicyServerConfigEntry{
			NamespacedName: types.NamespacedName{
				Namespace: admissionPolicy.GetNamespace(),
				Name:      admissionPolicy.GetName(),
			},
			URL:                   admissionPolicy.GetModule(),
			PolicyMode:            string(admissionPolicy.GetPolicyMode()),
			AllowedToMutate:       admissionPolicy.IsMutating(),
			Settings:              admissionPolicy.GetSettings(),
			ContextAwareResources: admissionPolicy.GetContextAwareResources(),
		}
	}
	return policies
}

func buildSourcesMap(policyServer *policiesv1.PolicyServer) PolicyServerSourcesEntry {
	sourcesEntry := PolicyServerSourcesEntry{}
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
