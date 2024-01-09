package resources

import (
	"context"
	"fmt"
	"net/url"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

const policyServerResource = "policyservers"

// Fetcher fetches all auditable resources.
// Uses a dynamic client to get all resources from the rules defined in a policy
type Fetcher struct {
	// dynamicClient is used to fetch resource data
	dynamicClient dynamic.Interface
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to fetch the policy server resources
	kubewardenNamespace string
	// FQDN of the policy server to query. If not empty, Fetcher will query on
	// port 3000. Useful for out-of-cluster debugging
	policyServerURL string
	// clientset is used to call the discovery API and see if a resource is
	// namespaced or not
	clientset kubernetes.Interface
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
func NewFetcher(kubewardenNamespace string, policyServerURL string) (*Fetcher, error) {
	config := ctrl.GetConfigOrDie()
	dynamicClient := dynamic.NewForConfigOrDie(config)
	clientset := kubernetes.NewForConfigOrDie(config)
	if policyServerURL != "" {
		log.Info().Msg(fmt.Sprintf("querying PolicyServers at %s for debugging purposes. Don't forget to start `kubectl port-forward` if needed", policyServerURL))
	}
	return &Fetcher{dynamicClient, kubewardenNamespace, policyServerURL, clientset}, nil
}

// GetResourcesForPolicies fetches all namespaced resources that must be audited
// in a specific namespace and returns them in an AuditableResources array.
// Iterates through all the rules in the policies to find all relevant resources. It creates a GVR (Group Version Resource)
// array for each rule defined in a policy. Then fetches and aggregates the GVRs for all the policies.
// Returns an array of AuditableResources. Each entry of the array will contain and array of resources of the same kind, and an array of
// policies that should evaluate these resources. Example:
// AuditableResources{Policies:[policy1, policy2] Resources:[podA, podB], Policies:[policy1] Resources:[deploymentA], Policies:[policy3] Resources:[ingressA]}
func (f *Fetcher) GetResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy, namespace string) ([]AuditableResources, error) {
	auditableResources := []AuditableResources{}
	gvrMap := createGVRPolicyMap(policies)
	for resourceFilter, policies := range gvrMap {
		isNamespaced, err := f.isNamespacedResource(resourceFilter.groupVersionResource)
		if err != nil {
			if apimachineryerrors.IsNotFound(err) {
				log.Warn().
					Str("resource GVK", resourceFilter.groupVersionResource.String()).
					Msg("API resource not found")
				continue
			}
			return nil, err
		}
		if !isNamespaced {
			// continue if resource is clusterwide
			continue
		}

		resources, err := f.getResourcesDynamically(ctx, &resourceFilter, namespace)
		if apimachineryerrors.IsNotFound(err) {
			// continue if resource doesn't exist
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", resourceFilter.groupVersionResource.String()).
					Str("ns", namespace),
				).Msg("API resource not found")
			continue
		}
		if apimachineryerrors.IsForbidden(err) {
			// continue if ServiceAccount lacks permissions, GVK may not exist, or
			// policies may be misconfigured
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", resourceFilter.groupVersionResource.String()).
					Str("ns", namespace),
				).Msg("API resource forbidden, unknown GVK or ServiceAccount lacks permissions")
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

// Method to check if the given resource is namespaced or not.
func (f *Fetcher) isNamespacedResource(gvr schema.GroupVersionResource) (bool, error) {
	discoveryClient := f.clientset.Discovery()

	apiResourceList, err := discoveryClient.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		return false, err
	}
	for _, apiResource := range apiResourceList.APIResources {
		if apiResource.Name == gvr.Resource {
			return apiResource.Namespaced, nil
		}
	}
	return false, apimachineryerrors.NewNotFound(gvr.GroupResource(), gvr.Resource)
}

// GetClusterWideResourcesForPolicies fetches all cluster wide resources that must be
// audited and returns them in an AuditableResources array. Iterates through all
// the rules in the ClusterAdmissionPolicy policies to find all relevant resources.
// It creates a GVR (Group Version Resource) array for each rule defined in a policy.
// Then fetches and aggregates the GVRs for all the policies. Returns an array of
// AuditableResources. Each entry of the array will contain and array of resources
// of the same kind, and an array of policies that should evaluate these resources.
// Example: AuditableResources{Policies:[policy1, policy2] Resources:[podA, podB], Policies:[policy1] Resources:[deploymentA], Policies:[policy3] Resources:[ingressA]}
func (f *Fetcher) GetClusterWideResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy) ([]AuditableResources, error) {
	auditableResources := []AuditableResources{}
	gvrMap := createGVRPolicyMap(policies)
	for resourceFilter, policies := range gvrMap {
		isNamespaced, err := f.isNamespacedResource(resourceFilter.groupVersionResource)
		if err != nil {
			if apimachineryerrors.IsNotFound(err) {
				log.Warn().
					Str("resource GVK", resourceFilter.groupVersionResource.String()).
					Msg("API resource not found")
				continue
			}
			return nil, err
		}
		if isNamespaced {
			continue
		}
		resources, err := f.getClusterWideResourcesDynamically(ctx, &resourceFilter)
		if apimachineryerrors.IsNotFound(err) {
			// continue if resource doesn't exist
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", resourceFilter.groupVersionResource.String()),
				).Msg("API resource not found")
			continue
		}
		if apimachineryerrors.IsForbidden(err) {
			// continue if ServiceAccount lacks permissions, GVK may not exist, or
			// policies may be misconfigured
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", resourceFilter.groupVersionResource.String()),
				).Msg("API resource forbidden, unknown GVK or ServiceAccount lacks permissions")
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
	resourceFilter *resourceFilter,
	namespace string) (
	*unstructured.UnstructuredList, error,
) {
	resourceID := schema.GroupVersionResource{
		Group:    resourceFilter.groupVersionResource.Group,
		Version:  resourceFilter.groupVersionResource.Version,
		Resource: resourceFilter.groupVersionResource.Resource,
	}
	var list *unstructured.UnstructuredList
	var err error
	listOptions := metav1.ListOptions{}
	if resourceFilter.objectSelector != nil {
		labelSelector := metav1.FormatLabelSelector(resourceFilter.objectSelector)
		listOptions = metav1.ListOptions{LabelSelector: labelSelector}
	}
	list, err = f.dynamicClient.Resource(resourceID).Namespace(namespace).List(ctx, listOptions)

	if err != nil {
		return nil, err
	}

	return list, nil
}

func (f *Fetcher) getClusterWideResourcesDynamically(ctx context.Context, resourceFilter *resourceFilter) (
	*unstructured.UnstructuredList, error,
) {
	resourceID := schema.GroupVersionResource{
		Group:    resourceFilter.groupVersionResource.Group,
		Version:  resourceFilter.groupVersionResource.Version,
		Resource: resourceFilter.groupVersionResource.Resource,
	}
	var list *unstructured.UnstructuredList
	var err error
	listOptions := metav1.ListOptions{}
	if resourceFilter.objectSelector != nil {
		labelSelector := metav1.FormatLabelSelector(resourceFilter.objectSelector)
		listOptions = metav1.ListOptions{LabelSelector: labelSelector}
	}
	list, err = f.dynamicClient.Resource(resourceID).List(ctx, listOptions)

	if err != nil {
		return nil, err
	}

	return list, nil
}

// The resourceFilter type is struct used to store the two piece of data needed
// to properly fetch the resources. The GroupVersionResource and LabelSelector.
// This type is used only inside the resources package.
type resourceFilter struct {
	groupVersionResource schema.GroupVersionResource
	objectSelector       *metav1.LabelSelector
}

func createGVRPolicyMap(policies []policiesv1.Policy) map[resourceFilter][]policiesv1.Policy {
	resources := make(map[resourceFilter][]policiesv1.Policy)
	for _, policy := range policies {
		addPolicyResources(resources, policy)
	}

	return resources
}

// All resources that matches the rules must be evaluated. Since rules provides an array of groups, another of version
// and another of resources we need to create all possible GVR from these arrays.
func addPolicyResources(resources map[resourceFilter][]policiesv1.Policy, policy policiesv1.Policy) {
	for _, rules := range policy.GetRules() {
		for _, resource := range rules.Resources {
			for _, version := range rules.APIVersions {
				for _, group := range rules.APIGroups {
					gvr := schema.GroupVersionResource{
						Group:    group,
						Version:  version,
						Resource: resource,
					}
					resourceFilter := resourceFilter{
						groupVersionResource: gvr,
						objectSelector:       policy.GetObjectSelector(),
					}
					resources[resourceFilter] = append(resources[resourceFilter], policy)
				}
			}
		}
	}
}

func getPolicyServerByName(ctx context.Context, policyServerName string, dynamicClient *dynamic.Interface) (*policiesv1.PolicyServer, error) {
	resourceID := schema.GroupVersionResource{
		Group:    policiesv1.GroupVersion.Group,
		Version:  policiesv1.GroupVersion.Version,
		Resource: policyServerResource,
	}
	resourceObj, err := (*dynamicClient).Resource(resourceID).Get(ctx, policyServerName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var policyServer policiesv1.PolicyServer
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(resourceObj.UnstructuredContent(), &policyServer)
	if err != nil {
		return nil, err
	}
	return &policyServer, nil
}

func getServiceByAppLabel(ctx context.Context, appLabel string, namespace string, dynamicClient *dynamic.Interface) (*v1.Service, error) {
	resourceID := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "services",
	}
	labelSelector := fmt.Sprintf("app=%s", appLabel)
	list, err := (*dynamicClient).Resource(resourceID).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}
	if len(list.Items) != 1 {
		return nil, fmt.Errorf("could not find a single service for the given policy server app label")
	}
	var service v1.Service
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[0].UnstructuredContent(), &service)
	if err != nil {
		return nil, err
	}
	return &service, nil
}

func (f *Fetcher) GetPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error) {
	policyServer, err := getPolicyServerByName(ctx, policy.GetPolicyServer(), &f.dynamicClient)
	if err != nil {
		return nil, err
	}
	service, err := getServiceByAppLabel(ctx, policyServer.AppLabel(), f.kubewardenNamespace, &f.dynamicClient)
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
