package resources

import (
	"context"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Fetcher fetches all auditable resources.
// Uses a dynamic client to get all resources from the rules defined in a policy
type Fetcher struct {
	dynamicClient dynamic.Interface
}

// AuditableResources represents all resources that must be audited for a group of policies.
// Example:
// AuditableResources{Policies:[policy1, policy2] Resources:[podA, podB], Policies:[policy1] Resources:[deploymentA]}
// means that podA and pobB must be evaluated by policy1 and policy2. deploymentA must be evaluated by policy1
type AuditableResources struct {
	Policies []policiesv1.Policy
	// It can be any kubernetes resource
	Resources []unstructured.Unstructured
}

// NewFetcher returns a new fetcher with a dynamic client
func NewFetcher() (*Fetcher, error) {
	config := ctrl.GetConfigOrDie()
	dynamicClient := dynamic.NewForConfigOrDie(config)

	return &Fetcher{dynamicClient}, nil
}

// GetResourcesForPolicies fetches all resources that must be audited and returns them in an AuditableResources array.
// Iterates through all the rules in the policies to find all relevant resources. It creates a GVR (Group Version Resource)
// array for each rule defined in a policy. Then fetches and aggregates the GVRs for all the policies.
// Returns an array of AuditableResources. Each entry of the array will contain and array of resources of the same kind, and an array of
// policies that should evaluate these resources. Example:
// AuditableResources{Policies:[policy1, policy2] Resources:[podA, podB], Policies:[policy1] Resources:[deploymentA], Policies:[policy3] Resources:[ingressA]}
func (f *Fetcher) GetResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy, namespace string) ([]AuditableResources, error) {
	auditableResources := []AuditableResources{}
	gvrMap := createGVRPolicyMap(policies)
	for gvr, policies := range gvrMap {
		resources, err := f.getResourcesDynamically(ctx, gvr.Group, gvr.Version, gvr.Resource, namespace)
		// continue if resource doesn't exist.
		if errors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(resources.Items) > 0 {
			auditableResources = append(auditableResources, AuditableResources{
				Policies:  policies,
				Resources: resources.Items,
			})
		}
	}

	return auditableResources, nil
}

func (f *Fetcher) getResourcesDynamically(ctx context.Context,
	group string, version string, resource string, namespace string) (
	*unstructured.UnstructuredList, error) {

	resourceId := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}
	list, err := f.dynamicClient.Resource(resourceId).Namespace(namespace).
		List(ctx, metav1.ListOptions{})

	if err != nil {
		return nil, err
	}

	return list, nil
}

func createGVRPolicyMap(policies []policiesv1.Policy) map[schema.GroupVersionResource][]policiesv1.Policy {
	resources := make(map[schema.GroupVersionResource][]policiesv1.Policy)
	for _, policy := range policies {
		addPolicyResources(resources, policy)
	}

	return resources
}

// All resources that matches the rules must be evaluated. Since rules provides an array of groups, another of version
// and another of resources we need to create all possible GVR from these arrays.
func addPolicyResources(resources map[schema.GroupVersionResource][]policiesv1.Policy, policy policiesv1.Policy) {
	for _, rules := range policy.GetRules() {
		for _, resource := range rules.Resources {
			for _, version := range rules.APIVersions {
				for _, group := range rules.APIGroups {
					gvr := schema.GroupVersionResource{
						Group:    group,
						Version:  version,
						Resource: resource,
					}
					resources[gvr] = append(resources[gvr], policy)
				}
			}
		}
	}
}
