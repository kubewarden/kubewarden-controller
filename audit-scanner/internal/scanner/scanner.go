package scanner

import (
	"errors"
	"fmt"
	"github.com/kubewarden/audit-scanner/internal/client"
)

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner interface {
	// ScanNamespace scans a given namespace
	ScanNamespace(namespace string) error
	// ScanAllNamespaces scan all namespaces
	ScanAllNamespaces() error
}

type scanner struct {
	client client.Client
}

func NewScanner(client client.Client) Scanner {
	return scanner{client: client}
}

func (s scanner) ScanNamespace(namespace string) error {
	policies, err := s.client.GetPoliciesForANamespace(namespace)
	if err != nil {
		return err
	}

	fmt.Println("The following policies were found for the namespace " + namespace)
	for _, policy := range policies {
		fmt.Println(policy.GetName())
	}

	return nil
}

func (s scanner) ScanAllNamespaces() error {
	return errors.New("Scanning all namespaces is not implemented yet. Please pass the --namespace flag to scan a namespace")
}
