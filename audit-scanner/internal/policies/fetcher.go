package policies

import (
	"context"
	"errors"
	"fmt"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kubewardenPoliciesGroup   = "policies.kubewarden.io"
	kubewardenPoliciesVersion = "v1"
)

// Fetcher fetches Kubewarden policies from the Kubernetes cluster, and filters policies that are auditable.
type Fetcher struct {
	client client.Client
	filter func(policies []policiesv1.Policy) []policiesv1.Policy
}

// NewFetcher returns a Fetcher. It will try to use in-cluster config, which will work just if audit-scanner is deployed
// inside a Pod. If in-cluster fails, it will try to fetch the kube config from the home dir. It will return an error
// if both attempts fail.
func NewFetcher() (*Fetcher, error) {
	client, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Fetcher{client: client, filter: filterAuditablePolicies}, nil
}

// TODO implement this for all ns
func (f *Fetcher) GetPoliciesForAllNamespaces() ([]policiesv1.Policy, error) {
	return nil, errors.New("scanning all namespaces is not implemented yet. Please pass the --namespace flag to scan a namespace")
}

// GetPoliciesForANamespace gets all auditable policies for a given namespace
func (f *Fetcher) GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, error) {
	namespacePolicies, err := f.findNamespacesForAllClusterAdmissionPolicies()
	if err != nil {
		return nil, fmt.Errorf("can't fetch ClusterAdmissionPolicies: %v", err)
	}
	admissionPolicies, err := f.getAdmissionPolicies(namespace)
	if err != nil {
		return nil, fmt.Errorf("can't fetch AdmissionPolicies: %v", err)
	}
	for _, policy := range admissionPolicies {
		namespacePolicies[namespace] = append(namespacePolicies[namespace], &policy)
	}

	return f.filter(namespacePolicies[namespace]), nil
}

// initializes map with an entry for all namespaces with an empty policies array as value
func (f *Fetcher) initNamespacePoliciesMap() (map[string][]policiesv1.Policy, error) {
	namespacePolicies := make(map[string][]policiesv1.Policy)
	namespaceList := &v1.NamespaceList{}
	err := f.client.List(context.Background(), namespaceList, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %v", err)
	}
	for _, namespace := range namespaceList.Items {
		namespacePolicies[namespace.Name] = []policiesv1.Policy{}
	}

	return namespacePolicies, nil
}

// returns a map with an entry per each namespace. Key is the namespace name, and value is an array of ClusterAdmissionPolicies
// that will evaluate resources within this namespace.
func (f *Fetcher) findNamespacesForAllClusterAdmissionPolicies() (map[string][]policiesv1.Policy, error) {
	namespacePolicies, err := f.initNamespacePoliciesMap()
	if err != nil {
		return nil, err
	}
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err = f.client.List(context.Background(), policies, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list AdmissionPolicies: %v", err)
	}

	for _, policy := range policies.Items {
		policy := policy
		namespaces, err := f.findNamespacesForClusterAdmissionPolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("can't find namespaces for ClusterAdmissionPolicy %s: %v", policy.Name, err)
		}
		for _, namespace := range namespaces {
			namespacePolicies[namespace.Name] = append(namespacePolicies[namespace.Name], &policy)
		}
	}

	return namespacePolicies, nil
}

// finds all namespaces where this ClusterAdmissionPolicy will evaluate resources. It uses the namespaceSelector field to filter the namespaces.
func (f *Fetcher) findNamespacesForClusterAdmissionPolicy(policy policiesv1.ClusterAdmissionPolicy) ([]v1.Namespace, error) {
	namespaceList := &v1.NamespaceList{}
	labelSelector, err := metav1.LabelSelectorAsSelector(policy.GetNamespaceSelector())
	if err != nil {
		return nil, err
	}
	opts := client.ListOptions{
		LabelSelector: labelSelector,
	}
	err = f.client.List(context.Background(), namespaceList, &opts)
	if err != nil {
		return nil, err
	}

	return namespaceList.Items, nil
}

func (f *Fetcher) getAdmissionPolicies(namespace string) ([]policiesv1.AdmissionPolicy, error) {
	policies := &policiesv1.AdmissionPolicyList{}
	err := f.client.List(context.Background(), policies, &client.ListOptions{Namespace: namespace})
	if err != nil {
		return nil, err
	}

	return policies.Items, nil
}

func newClient() (client.Client, error) {
	config := ctrl.GetConfigOrDie()
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion}, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion})

	return client.New(config, client.Options{Scheme: customScheme})
}
