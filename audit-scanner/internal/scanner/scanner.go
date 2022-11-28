package scanner

import (
	"context"
	"errors"
	"fmt"
	"github.com/kubewarden/audit-scanner/internal/resources"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog/log"
)

// A PoliciesFetcher interacts with the kubernetes api to return Kubewarden policies
type PoliciesFetcher interface {
	// GetPoliciesForANamespace gets all auditable policies for a given namespace
	GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, error)
	// GetPoliciesForAllNamespaces gets all auditable policies for all namespaces
	GetPoliciesForAllNamespaces() ([]policiesv1.Policy, error)
}

type ResourcesFetcher interface {
	GetResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy, namespace string) ([]resources.AuditableResources, error)
}

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	policiesFetcher  PoliciesFetcher
	resourcesFetcher ResourcesFetcher
}

// NewScanner creates a new scanner with the PoliciesFetcher provided
func NewScanner(policiesFetcher PoliciesFetcher, resourcesFetcher ResourcesFetcher) *Scanner {
	return &Scanner{policiesFetcher, resourcesFetcher}
}

// ScanNamespace scans resources for a given namespace
func (s *Scanner) ScanNamespace(namespace string) error {
	log.Info().Str("namespace", namespace).Msg("scan started")

	policies, err := s.policiesFetcher.GetPoliciesForANamespace(namespace)
	if err != nil {
		return err
	}
	log.Debug().Str("namespace", namespace).Int("count", len(policies)).Msg("number of policies to evaluate")

	// TODO continue with the scanning and remove this code
	fmt.Println("The following policies were found for the namespace " + namespace)
	for _, policy := range policies {
		fmt.Println(policy.GetName())
	}

	auditableResources, err := s.resourcesFetcher.GetResourcesForPolicies(context.Background(), policies, namespace)

	if err != nil {
		return err
	}

	// TODO this is for debugging, it should be remove in future steps!
	for _, resource := range auditableResources {
		fmt.Println("Policies: ")
		for _, policy := range resource.Policies {
			fmt.Println(policy.GetName())
		}
		for _, resource := range resource.Resources {
			fmt.Println(resource)
			fmt.Println("........")
		}
		fmt.Println("---------------------")
	}

	// TODO for next steps:
	// Iterate through all auditableResources. Each item contains a list of resources and the policies that would need
	// to evaluate them. You need to create the AdmissionReview request using the resource which is an unstructured.
	// unstructured nested functions might help with that https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1/unstructured
	// or the UnstructuredContent() method that returns a map

	return nil
}

// ScanAllNamespaces scans resources for all namespaces
func (s *Scanner) ScanAllNamespaces() error {
	return errors.New("Scanning all namespaces is not implemented yet. Please pass the --namespace flag to scan a namespace")
}
