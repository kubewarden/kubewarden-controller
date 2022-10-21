package client

import (
	"context"
	"errors"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kubewardenPoliciesGroup   = "policies.kubewarden.io"
	kubewardenPoliciesVersion = "v1"
)

// NamespacePolicies represents a map where the key is a namespace name, and the value are all policies that applies to this namespace
type NamespacePolicies map[string][]policiesv1.Policy

// A Client interacts with the kubernetes api
type Client interface {
	// GetPoliciesForANamespace gets all policies for a given namespace
	GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, error)
	// GetPoliciesForAllNamespaces gets all policies for all namespaces
	GetPoliciesForAllNamespaces() ([]policiesv1.Policy, error)
}

type client struct {
	k8sClient k8sClient.Client
}

// NewClient returns a client. It will try to use in-cluster config, which will work just if audit-scanner is deployed
// inside a Pod. If in-cluster fails, it will try to fetch the kube config from the home dir. It will return an error
// if both attempts fail.
func NewClient() (Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return newClientFromHomeConfig()
	}

	return newClient(config)
}

func newClientFromHomeConfig() (Client, error) {
	var kubeConfig string
	if home := homedir.HomeDir(); home != "" {
		kubeConfig = filepath.Join(home, ".kube", "config")
	} else {
		return nil, errors.New("can't get kubeconfig from home dir")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return nil, err
	}

	return newClient(config)
}

func newClient(config *rest.Config) (Client, error) {
	// register Kubewarden policies in scheme
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion}, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion})

	k8sClient, err := k8sClient.New(config, k8sClient.Options{Scheme: customScheme})

	if err != nil {
		return nil, err
	}

	return client{k8sClient}, nil
}

// TODO implement this for all ns
func (c client) GetPoliciesForAllNamespaces() ([]policiesv1.Policy, error) {
	return nil, errors.New("Scanning all namespaces is not implemented yet. Please pass the --namespace flag to scan a namespace")
}

// GetPoliciesForANamespace gets all policies for a given namespace
func (c client) GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, error) {
	namespacePolicies, err := c.findNamespacesForAllClusterAdmissionPolicies()
	if err != nil {
		return nil, err
	}
	admissionPolicies, err := c.getAdmissionPolicies(namespace)
	if err != nil {
		return nil, err
	}
	policies := []policiesv1.Policy{}
	for _, policy := range admissionPolicies {
		policies = append(policies, &policy)
	}
	createOrAppendPoliciesIfExist(namespacePolicies, namespace, policies...)

	return namespacePolicies[namespace], nil
}

func (c client) findNamespacesForAllClusterAdmissionPolicies() (NamespacePolicies, error) {
	namespacePolicies := make(NamespacePolicies)
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err := c.k8sClient.List(context.Background(), policies, &k8sClient.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, policy := range policies.Items {
		policy := policy
		namespaces, err := c.findNamespacesForClusterAdmissionPolicy(policy)
		if err != nil {
			return nil, err
		}
		for _, namespace := range namespaces {
			createOrAppendPoliciesIfExist(namespacePolicies, namespace.Name, &policy)
		}
	}

	return namespacePolicies, nil
}

func (c client) findNamespacesForClusterAdmissionPolicy(policy policiesv1.ClusterAdmissionPolicy) ([]v1.Namespace, error) {
	namespaceList := &v1.NamespaceList{}
	labelSelector, err := metav1.LabelSelectorAsSelector(policy.GetNamespaceSelector())
	if err != nil {
		return nil, err
	}
	opts := k8sClient.ListOptions{
		LabelSelector: labelSelector,
	}
	err = c.k8sClient.List(context.Background(), namespaceList, &opts)
	if err != nil {
		return nil, err
	}

	return namespaceList.Items, nil
}

func (c client) getAdmissionPolicies(namespace string) ([]policiesv1.AdmissionPolicy, error) {
	policies := &policiesv1.AdmissionPolicyList{}
	err := c.k8sClient.List(context.Background(), policies, &k8sClient.ListOptions{Namespace: namespace})
	if err != nil {
		return nil, err
	}

	return policies.Items, nil
}

func createOrAppendPoliciesIfExist(namespacePolicies NamespacePolicies, namespace string, policies ...policiesv1.Policy) {
	if namespacePolicies[namespace] == nil {
		namespacePolicies[namespace] = policies
	} else {
		namespacePolicies[namespace] = append(namespacePolicies[namespace], policies...)
	}
}
