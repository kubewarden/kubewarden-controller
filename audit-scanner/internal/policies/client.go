package policies

import (
	"context"
	"fmt"
	"net/url"
	"slices"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog/log"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A client to get Kubewarden policies from the Kubernetes cluster
type Client struct {
	// client is a controller-runtime client extended with the Kubewarden CRDs
	client client.Client
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to get the policy server resources
	kubewardenNamespace string
	// FQDN of the policy server to query. If not empty, it will query on port 3000.
	// Useful for out-of-cluster debugging
	policyServerURL string
}

// Policies represents a collection of auditable policies
type Policies struct {
	// PoliciesByGVR a map of policies grouped by GVR
	PoliciesByGVR map[schema.GroupVersionResource][]*Policy
	// PolicyNum represents the number of policies
	PolicyNum int
	// SkippedNum represents the number of skipped policies that don't match audit constraints
	SkippedNum int
	// ErroredNum represents the number of errored policies. These policies may be misconfigured
	ErroredNum int
}

// Policy represents a policy and the URL of the policy server where it is running
type Policy struct {
	policiesv1.Policy
	PolicyServer *url.URL
}

// NewClient returns a policy Client
func NewClient(client client.Client, kubewardenNamespace string, policyServerURL string) (*Client, error) {
	if policyServerURL != "" {
		log.Info().Msg(fmt.Sprintf("querying PolicyServers at %s for debugging purposes. Don't forget to start `kubectl port-forward` if needed", policyServerURL))
	}

	return &Client{
		client:              client,
		kubewardenNamespace: kubewardenNamespace,
		policyServerURL:     policyServerURL,
	}, nil
}

// GetPoliciesForANamespace gets all the auditable policies for a given namespace
func (f *Client) GetPoliciesForANamespace(ctx context.Context, namespace string) (*Policies, error) {
	namespacePolicies, err := f.findNamespacesForAllClusterAdmissionPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't get ClusterAdmissionPolicies: %w", err)
	}
	admissionPolicies, err := f.getAdmissionPolicies(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("can't get AdmissionPolicies: %w", err)
	}
	for _, policy := range admissionPolicies {
		policy := policy
		namespacePolicies[namespace] = append(namespacePolicies[namespace], &policy)
	}

	return f.groupPoliciesByGVR(ctx, namespacePolicies[namespace], true)
}

func (f *Client) getClusterAdmissionPolicies(ctx context.Context) ([]policiesv1.ClusterAdmissionPolicy, error) {
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err := f.client.List(ctx, policies)
	if err != nil {
		return []policiesv1.ClusterAdmissionPolicy{}, err
	}
	return policies.Items, nil
}

// GetClusterWidePolicies returns all the auditable cluster-wide policies
func (f *Client) GetClusterWidePolicies(ctx context.Context) (*Policies, error) {
	clusterAdmissionPolicies, err := f.getClusterAdmissionPolicies(ctx)
	if err != nil {
		return nil, err
	}
	policies := []policiesv1.Policy{}
	for _, policy := range clusterAdmissionPolicies {
		policy := policy
		policies = append(policies, &policy)
	}

	return f.groupPoliciesByGVR(ctx, policies, false)
}

// initializes map with an entry for all namespaces with an empty policies array as value
func (f *Client) initNamespacePoliciesMap(ctx context.Context) (map[string][]policiesv1.Policy, error) {
	namespacePolicies := make(map[string][]policiesv1.Policy)
	namespaceList := &corev1.NamespaceList{}
	err := f.client.List(ctx, namespaceList, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %w", err)
	}
	for _, namespace := range namespaceList.Items {
		namespacePolicies[namespace.Name] = []policiesv1.Policy{}
	}

	return namespacePolicies, nil
}

// returns a map with an entry per each namespace. Key is the namespace name, and value is an array of ClusterAdmissionPolicies
// that will evaluate resources within this namespace.
func (f *Client) findNamespacesForAllClusterAdmissionPolicies(ctx context.Context) (map[string][]policiesv1.Policy, error) {
	namespacePolicies, err := f.initNamespacePoliciesMap(ctx)
	if err != nil {
		return nil, err
	}
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err = f.client.List(ctx, policies, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list ClusterAdmissionPolicies: %w", err)
	}

	for _, policy := range policies.Items {
		policy := policy
		namespaces, err := f.findNamespacesForClusterAdmissionPolicy(ctx, policy)
		if err != nil {
			return nil, fmt.Errorf("can't find namespaces for ClusterAdmissionPolicy %s: %w", policy.Name, err)
		}
		for _, namespace := range namespaces {
			namespacePolicies[namespace.Name] = append(namespacePolicies[namespace.Name], &policy)
		}
	}

	return namespacePolicies, nil
}

// finds all namespaces where this ClusterAdmissionPolicy will evaluate resources. It uses the namespaceSelector field to filter the namespaces.
func (f *Client) findNamespacesForClusterAdmissionPolicy(ctx context.Context, policy policiesv1.ClusterAdmissionPolicy) ([]corev1.Namespace, error) {
	namespaceList := &corev1.NamespaceList{}
	labelSelector, err := metav1.LabelSelectorAsSelector(policy.GetUpdatedNamespaceSelector(f.kubewardenNamespace))
	if err != nil {
		return nil, err
	}
	opts := client.ListOptions{
		LabelSelector: labelSelector,
	}
	err = f.client.List(ctx, namespaceList, &opts)
	if err != nil {
		return nil, err
	}

	return namespaceList.Items, nil
}

func (f *Client) getAdmissionPolicies(ctx context.Context, namespace string) ([]policiesv1.AdmissionPolicy, error) {
	policies := &policiesv1.AdmissionPolicyList{}
	err := f.client.List(ctx, policies, &client.ListOptions{Namespace: namespace})
	if err != nil {
		return nil, err
	}

	return policies.Items, nil
}

// groupPoliciesByGVRAndLabelSelectorg groups policies by GVR.
// If namespaced is true, it will skip cluster-wide resources, otherwise it will skip namespaced resources.
// If the policy targets an unknown GVR or the policy server URL cannot be constructed, the policy will be counted as errored.
func (f *Client) groupPoliciesByGVR(ctx context.Context, policies []policiesv1.Policy, namespaced bool) (*Policies, error) { //nolint:funlen
	policiesByGVR := make(map[schema.GroupVersionResource][]*Policy)
	auditablePolicies := map[string]struct{}{}
	skippedPolicies := map[string]struct{}{}
	erroredPolicies := map[string]struct{}{}

	for _, policy := range policies {
		rules := filterWildcardRules(policy.GetRules())
		if len(rules) == 0 {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			log.
				Debug().
				Str("policy", policy.GetUniqueName()).
				Msg("the policy targets only wildcard resources, skipping...")

			continue
		}

		rules = filterNonCreateOperations(rules)
		if len(rules) == 0 {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			log.
				Debug().
				Str("policy", policy.GetUniqueName()).
				Msg("the policy does not have rules with a CREATE operation, skipping...")

			continue
		}

		groupVersionResources, err := f.getGroupVersionResources(rules, namespaced)
		if err != nil {
			erroredPolicies[policy.GetUniqueName()] = struct{}{}
			log.Error().Err(err).Str("policy", policy.GetUniqueName()).Msg("failed to obtain unknown GroupVersion resources. The policy may be misconfigured, skipping as error...")
			continue
		}

		if len(groupVersionResources) == 0 {
			log.
				Debug().
				Str("policy", policy.GetUniqueName()).
				Bool("namespaced", namespaced).
				Msg("the policy does not target resources within the selected scope")

			continue
		}

		if !policy.GetBackgroundAudit() {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			log.Debug().Str("policy", policy.GetUniqueName()).Msg("the policy has backgroundAudit set to false, skipping...")

			continue
		}

		if policy.GetStatus().PolicyStatus != policiesv1.PolicyStatusActive {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			log.Debug().Str("policy", policy.GetUniqueName()).Msg("the policy is not active, skipping...")

			continue
		}

		url, err := f.getPolicyServerURLRunningPolicy(ctx, policy)
		if err != nil {
			erroredPolicies[policy.GetUniqueName()] = struct{}{}
			log.Error().Err(err).Str("policy", policy.GetUniqueName()).Msg("failed to obtain matching policy-server URL, skipping as error...")
			continue
		}

		auditablePolicies[policy.GetUniqueName()] = struct{}{}
		policy := &Policy{
			Policy:       policy,
			PolicyServer: url,
		}

		for _, gvr := range groupVersionResources {
			addPolicyToMap(policiesByGVR, gvr, policy)
		}
	}

	return &Policies{
		PoliciesByGVR: policiesByGVR,
		PolicyNum:     len(auditablePolicies),
		SkippedNum:    len(skippedPolicies),
		ErroredNum:    len(erroredPolicies),
	}, nil
}

func addPolicyToMap(policiesByGVR map[schema.GroupVersionResource][]*Policy, gvr schema.GroupVersionResource, policy *Policy) {
	value, found := policiesByGVR[gvr]
	if !found {
		policiesByGVR[gvr] = []*Policy{policy}
	} else {
		policiesByGVR[gvr] = append(value, policy)
	}
}

// getGroupVersionResources returns a list of GroupVersionResource from a list of policies.
// if namespaced is true, it will skip cluster-wide resources, otherwise it will skip namespaced resources.
func (f *Client) getGroupVersionResources(rules []admissionregistrationv1.RuleWithOperations, namespaced bool) ([]schema.GroupVersionResource, error) {
	var groupVersionResources []schema.GroupVersionResource

	for _, rule := range rules {
		for _, resource := range rule.Resources {
			for _, version := range rule.APIVersions {
				for _, group := range rule.APIGroups {
					gvr := schema.GroupVersionResource{
						Group:    group,
						Version:  version,
						Resource: resource,
					}
					isNamespaced, err := f.isNamespacedResource(gvr)
					if err != nil {
						return nil, err
					}
					if namespaced && !isNamespaced {
						// continue if resource is clusterwide
						continue
					}
					if !namespaced && isNamespaced {
						// continue if resource is namespaced
						continue
					}

					groupVersionResources = append(groupVersionResources, gvr)
				}
			}
		}
	}

	return groupVersionResources, nil
}

// isNamespacedResource checks if the given resource is namespaced or not.
func (f *Client) isNamespacedResource(gvr schema.GroupVersionResource) (bool, error) {
	gvk, err := f.client.RESTMapper().KindFor(gvr)
	if err != nil {
		return false, err
	}

	mapping, err := f.client.RESTMapper().RESTMapping(gvk.GroupKind(), gvr.Version)
	if err != nil {
		return false, err
	}

	return mapping.Scope.Name() == meta.RESTScopeNameNamespace, nil
}

func (f *Client) getPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error) {
	policyServer, err := f.getPolicyServerByName(ctx, policy.GetPolicyServer())
	if err != nil {
		return nil, err
	}
	service, err := f.getServiceByAppLabel(ctx, policyServer.AppLabel(), f.kubewardenNamespace)
	if err != nil {
		return nil, err
	}
	if len(service.Spec.Ports) < 1 {
		return nil, fmt.Errorf("policy server service does not have a port")
	}
	var urlStr string
	if f.policyServerURL != "" {
		url, err := url.Parse(f.policyServerURL)
		if err != nil {
			log.Fatal().Msg("incorrect URL for policy-server")
		}
		urlStr = fmt.Sprintf("%s/audit/%s", url, policy.GetUniqueName())
	} else {
		urlStr = fmt.Sprintf("https://%s.%s.svc:%d/audit/%s", service.Name, f.kubewardenNamespace, service.Spec.Ports[0].Port, policy.GetUniqueName())
	}
	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return url, nil
}

func (f *Client) getPolicyServerByName(ctx context.Context, policyServerName string) (*policiesv1.PolicyServer, error) {
	var policyServer policiesv1.PolicyServer

	err := f.client.Get(ctx, client.ObjectKey{Name: policyServerName}, &policyServer)
	if err != nil {
		return nil, err
	}

	return &policyServer, nil
}

func (f *Client) getServiceByAppLabel(ctx context.Context, appLabel string, namespace string) (*corev1.Service, error) {
	serviceList := corev1.ServiceList{}
	err := f.client.List(ctx, &serviceList, &client.ListOptions{Namespace: namespace}, &client.MatchingLabels{"app": appLabel})
	if err != nil {
		return nil, err
	}

	if len(serviceList.Items) != 1 {
		return nil, fmt.Errorf("could not find a single service for the given policy server app label")
	}

	return &serviceList.Items[0], nil
}

// filterWildcardRules filters out rules that contain a wildcard in the APIGroups, APIVersions or Resources fields
func filterWildcardRules(rules []admissionregistrationv1.RuleWithOperations) []admissionregistrationv1.RuleWithOperations {
	filteredRules := []admissionregistrationv1.RuleWithOperations{}
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, "*") ||
			slices.Contains(rule.APIVersions, "*") ||
			slices.Contains(rule.Resources, "*") {
			continue
		}
		filteredRules = append(filteredRules, rule)
	}

	return filteredRules
}

// filterNonCreateOperations filters out rules that do not contain a CREATE operation
func filterNonCreateOperations(rules []admissionregistrationv1.RuleWithOperations) []admissionregistrationv1.RuleWithOperations {
	filteredRules := []admissionregistrationv1.RuleWithOperations{}
	for _, rule := range rules {
		for _, operation := range rule.Operations {
			if operation == admissionregistrationv1.Create {
				filteredRules = append(filteredRules, rule)
			}
		}
	}

	return filteredRules
}
