package policies

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client fetches Kubewarden policies from the Kubernetes cluster.
type Client struct {
	// client is a controller-runtime client extended with the Kubewarden CRDs
	client client.Client
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to get the policy server resources
	kubewardenNamespace string
	// FQDN of the policy server to query. If not empty, it will query on port 3000.
	// Useful for out-of-cluster debugging
	policyServerURL string
	// logger is used to log the messages
	logger *slog.Logger
}

// Policies represents a collection of auditable policies.
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

// Policy represents a policy and the URL of the policy server where it is running.
type Policy struct {
	policiesv1.Policy
	PolicyServer *url.URL
}

// NewClient returns a policy Client.
func NewClient(client client.Client, kubewardenNamespace string, policyServerURL string, logger *slog.Logger) (*Client, error) {
	if policyServerURL != "" {
		logger.Info(fmt.Sprintf("querying PolicyServers at %s for debugging purposes. Don't forget to start `kubectl port-forward` if needed", policyServerURL))
	}

	return &Client{
		client:              client,
		kubewardenNamespace: kubewardenNamespace,
		policyServerURL:     policyServerURL,
		logger:              logger.With("client", "policyclient"),
	}, nil
}

// GetPoliciesByNamespace gets all the auditable policies for a given namespace.
func (f *Client) GetPoliciesByNamespace(ctx context.Context, namespace *corev1.Namespace) (*Policies, error) {
	var policies []policiesv1.Policy

	clusterAdmissionPolicies, err := f.findClusterAdmissionPoliciesByNamespace(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ClusterAdmissionPolicies for namespace %q: %w", namespace, err)
	}
	for _, policy := range clusterAdmissionPolicies {
		policies = append(policies, &policy)
	}

	clusterAdmissionPolicyGroups, err := f.findClusterAdmissionPolicyGroupsByNamespace(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ClusterAdmissionPolicyGroups for namespace %q: %w", namespace, err)
	}
	for _, policy := range clusterAdmissionPolicyGroups {
		policies = append(policies, &policy)
	}

	admissionPolicies, err := f.listAdmissionPolicies(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AdmissionPolicies for namespace %q: %w", namespace, err)
	}
	for _, policy := range admissionPolicies {
		policies = append(policies, &policy)
	}

	admissionPolicyGroups, err := f.listAdmissionPolicyGroups(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AdmissionPolicyGroups for namespace %q: %w", namespace, err)
	}
	for _, policy := range admissionPolicyGroups {
		policies = append(policies, &policy)
	}

	return f.groupPoliciesByGVR(ctx, policies, true)
}

// GetClusterWidePolicies returns all the auditable cluster-wide policies.
func (f *Client) GetClusterWidePolicies(ctx context.Context) (*Policies, error) {
	var policies []policiesv1.Policy

	clusterAdmissionPolicies, err := f.listClusterAdmissionPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve cluster-wide ClusterAdmissionPolicies: %w", err)
	}
	for _, policy := range clusterAdmissionPolicies {
		policies = append(policies, &policy)
	}

	clusterAdmissionPolicyGroups, err := f.listClusterAdmissionPolicyGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve cluster-wide ClusterAdmissionPolicyGroups: %w", err)
	}
	for _, policy := range clusterAdmissionPolicyGroups {
		policies = append(policies, &policy)
	}

	return f.groupPoliciesByGVR(ctx, policies, false)
}

// findClusterAdmissionPoliciesByNamespace returns all the ClusterAdmissionPolicies that evaluate resources in the given namespace.
func (f *Client) findClusterAdmissionPoliciesByNamespace(ctx context.Context, namespace *corev1.Namespace) ([]policiesv1.ClusterAdmissionPolicy, error) {
	clusterAdmissionPolicies, err := f.listClusterAdmissionPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var result []policiesv1.ClusterAdmissionPolicy

	for _, policy := range clusterAdmissionPolicies {
		matches, err := policyMatchesNamespace(&policy, namespace)
		if err != nil {
			return nil, err
		}

		if matches {
			result = append(result, policy)
		}
	}

	return result, nil
}

// findClusterAdmissionPolicyGroupsByNamespace returns all the ClusterAdmissionPolicyGroups that evaluate resources in the given namespace.
func (f *Client) findClusterAdmissionPolicyGroupsByNamespace(ctx context.Context, namespace *corev1.Namespace) ([]policiesv1.ClusterAdmissionPolicyGroup, error) {
	clusterAdmissionPolicyGroups, err := f.listClusterAdmissionPolicyGroups(ctx)
	if err != nil {
		return nil, err
	}

	var result []policiesv1.ClusterAdmissionPolicyGroup
	for _, policy := range clusterAdmissionPolicyGroups {
		matches, err := policyMatchesNamespace(&policy, namespace)
		if err != nil {
			return nil, err
		}

		if matches {
			result = append(result, policy)
		}
	}

	return result, nil
}

// listClusterAdmissionPolicies returns all the ClusterAdmissionPolicies in the cluster.
func (f *Client) listClusterAdmissionPolicies(ctx context.Context) ([]policiesv1.ClusterAdmissionPolicy, error) {
	var clusterAdmissionPolicyList policiesv1.ClusterAdmissionPolicyList

	err := f.client.List(ctx, &clusterAdmissionPolicyList)
	if err != nil {
		return nil, fmt.Errorf("cannot list ClusterAdmissionPolicies: %w", err)
	}

	return clusterAdmissionPolicyList.Items, nil
}

// listClusterAdmissionPolicyGroups returns all the ClusterAdmissionPolicyGroups in the cluster.
func (f *Client) listClusterAdmissionPolicyGroups(ctx context.Context) ([]policiesv1.ClusterAdmissionPolicyGroup, error) {
	var clusterAdmissionPolicyGroupList policiesv1.ClusterAdmissionPolicyGroupList

	err := f.client.List(ctx, &clusterAdmissionPolicyGroupList)
	if err != nil {
		return nil, fmt.Errorf("cannot list ClusterAdmissionPolicies: %w", err)
	}

	return clusterAdmissionPolicyGroupList.Items, nil
}

// listAdmissionPolicies returns all the AdmissionPolicies in the given namespace.
func (f *Client) listAdmissionPolicies(ctx context.Context, namespace *corev1.Namespace) ([]policiesv1.AdmissionPolicy, error) {
	var admissionPolicyList policiesv1.AdmissionPolicyList

	err := f.client.List(ctx, &admissionPolicyList, &client.ListOptions{Namespace: namespace.GetName()})
	if err != nil {
		return nil, fmt.Errorf("cannot list AdmissionPolicy groups: %w", err)
	}

	return admissionPolicyList.Items, nil
}

// listClusterAdmissionPolicyGroups returns all the ClusterAdmissionPolicyGroups in the cluster.
func (f *Client) listAdmissionPolicyGroups(ctx context.Context, namespace *corev1.Namespace) ([]policiesv1.AdmissionPolicyGroup, error) {
	var admissionPolicyGroupList policiesv1.AdmissionPolicyGroupList

	err := f.client.List(ctx, &admissionPolicyGroupList, &client.ListOptions{Namespace: namespace.GetName()})
	if err != nil {
		return nil, fmt.Errorf("cannot list AdmissionPolicies: %w", err)
	}

	return admissionPolicyGroupList.Items, nil
}

// policyMatchesNamespace checks if the policy matches the namespace.
func policyMatchesNamespace(policy policiesv1.Policy, namespace *corev1.Namespace) (bool, error) {
	if policy.GetNamespaceSelector() == nil {
		return true, nil
	}

	labelSelector, err := metav1.LabelSelectorAsSelector(policy.GetNamespaceSelector())
	if err != nil {
		return false, err
	}

	return labelSelector.Matches(labels.Set(namespace.Labels)), nil
}

// groupPoliciesByGVRAndLabelSelectorg groups policies by GVR.
// If namespaced is true, it will skip cluster-wide resources, otherwise it will skip namespaced resources.
// If the policy targets an unknown GVR or the policy server URL cannot be constructed, the policy will be counted as errored.
func (f *Client) groupPoliciesByGVR(ctx context.Context, policies []policiesv1.Policy, namespaced bool) (*Policies, error) {
	policiesByGVR := make(map[schema.GroupVersionResource][]*Policy)
	auditablePolicies := map[string]struct{}{}
	skippedPolicies := map[string]struct{}{}
	erroredPolicies := map[string]struct{}{}

	for _, policy := range policies {
		rules := filterWildcardRules(policy.GetRules())
		if len(rules) == 0 {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			f.logger.DebugContext(ctx, "the policy targets only wildcard resources, skipping...", slog.String("policy", policy.GetUniqueName()))

			continue
		}

		rules = filterNonCreateOperations(rules)
		if len(rules) == 0 {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			f.logger.DebugContext(ctx, "the policy does not have rules with a CREATE operation, skipping...", slog.String("policy", policy.GetUniqueName()))

			continue
		}

		groupVersionResources, err := f.getGroupVersionResources(rules, namespaced)
		if err != nil {
			erroredPolicies[policy.GetUniqueName()] = struct{}{}
			f.logger.ErrorContext(ctx, "failed to obtain unknown GroupVersion resources. The policy may be misconfigured, skipping as error...",
				slog.String("error", err.Error()),
				slog.String("policy", policy.GetUniqueName()))
			continue
		}

		if len(groupVersionResources) == 0 {
			f.logger.DebugContext(ctx, "the policy does not target resources within the selected scope",
				slog.String("policy", policy.GetUniqueName()),
				slog.Bool("namespaced", namespaced))

			continue
		}

		if !policy.GetBackgroundAudit() {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			f.logger.DebugContext(ctx, "the policy has backgroundAudit set to false, skipping...",
				slog.String("policy", policy.GetUniqueName()))

			continue
		}

		if policy.GetStatus().PolicyStatus != policiesv1.PolicyStatusActive {
			skippedPolicies[policy.GetUniqueName()] = struct{}{}
			f.logger.DebugContext(ctx, "the policy is not active, skipping...", slog.String("policy", policy.GetUniqueName()))

			continue
		}

		url, err := f.getPolicyServerURLRunningPolicy(ctx, policy)
		if err != nil {
			erroredPolicies[policy.GetUniqueName()] = struct{}{}
			f.logger.ErrorContext(ctx, "failed to obtain matching policy-server URL, skipping as error...",
				slog.String("error", err.Error()),
				slog.String("policy", policy.GetUniqueName()))
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

func getRuleGVRs(rule admissionregistrationv1.RuleWithOperations) []schema.GroupVersionResource {
	gvrs := []schema.GroupVersionResource{}
	for _, resource := range rule.Resources {
		for _, version := range rule.APIVersions {
			for _, group := range rule.APIGroups {
				gvrs = append(gvrs, schema.GroupVersionResource{
					Group:    group,
					Version:  version,
					Resource: resource,
				})
			}
		}
	}
	return gvrs
}

// getGroupVersionResources returns a list of GroupVersionResource from a list of policies.
// if namespaced is true, it will skip cluster-wide resources, otherwise it will skip namespaced resources.
func (f *Client) getGroupVersionResources(rules []admissionregistrationv1.RuleWithOperations, namespaced bool) ([]schema.GroupVersionResource, error) {
	var groupVersionResources []schema.GroupVersionResource

	for _, rule := range rules {
		gvrs := getRuleGVRs(rule)
		for _, gvr := range gvrs {
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
	service, err := f.getServiceByInstanceLabel(ctx, policyServer.NameWithPrefix(), f.kubewardenNamespace)
	if err != nil {
		return nil, err
	}
	if len(service.Spec.Ports) < 1 {
		return nil, errors.New("policy server service does not have a port")
	}
	var urlStr string
	if f.policyServerURL != "" {
		url, err := url.Parse(f.policyServerURL)
		if err != nil {
			return nil, err
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

func (f *Client) getServiceByInstanceLabel(ctx context.Context, instanceName string, namespace string) (*corev1.Service, error) {
	serviceList := corev1.ServiceList{}
	err := f.client.List(ctx, &serviceList, &client.ListOptions{Namespace: namespace}, &client.MatchingLabels{"app.kubernetes.io/instance": instanceName})
	if err != nil {
		return nil, err
	}

	if len(serviceList.Items) != 1 {
		return nil, errors.New("could not find a single service for the given policy server instance label")
	}

	return &serviceList.Items[0], nil
}

// filterWildcardRules filters out rules that contain a wildcard in the APIGroups, APIVersions or Resources fields.
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

// filterNonCreateOperations filters out rules that do not contain a CREATE operation.
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
