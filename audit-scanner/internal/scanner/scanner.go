package scanner

import (
	"errors"
	"fmt"
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

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	fetcher PoliciesFetcher
}

// NewScanner creates a new scanner with the PoliciesFetcher provided
func NewScanner(fetcher PoliciesFetcher) *Scanner {
	return &Scanner{fetcher}
}

// ScanNamespace scans resources for a given namespace
func (s *Scanner) ScanNamespace(namespace string) error {
	log.Info().Str("namespace", namespace).Msg("scan started")

	policies, err := s.fetcher.GetPoliciesForANamespace(namespace)
	if err != nil {
		return err
	}
	log.Debug().Str("namespace", namespace).Int("count", len(policies)).Msg("number of policies to evaluate")

	// TODO continue with the scanning and remove this code
	fmt.Println("The following policies were found for the namespace " + namespace)
	for _, policy := range policies {
		fmt.Println(policy.GetName())
	}

	return nil
}

// ScanAllNamespaces scans resources for all namespaces
func (s *Scanner) ScanAllNamespaces() error {
	return errors.New("Scanning all namespaces is not implemented yet. Please pass the --namespace flag to scan a namespace")
}
