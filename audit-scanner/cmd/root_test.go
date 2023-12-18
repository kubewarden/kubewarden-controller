package cmd

import (
	"testing"
)

func TestStartScannerForANamespace(t *testing.T) {
	const namespace = "default"
	mockScanner := mockScanner{}

	err := startScanner(namespace, false, &mockScanner)
	if err != nil {
		t.Errorf("err should be nil, but got %s", err.Error())
	}
	if mockScanner.scanNamespaceCalledWith != namespace {
		t.Errorf("scanNamespace should have been called with %s, but got %s", namespace, mockScanner.scanNamespaceCalledWith)
	}
	if mockScanner.scanAllNamespacesCalled == true {
		t.Errorf("scanAllNamespaces should have not been called")
	}
	if mockScanner.scanClusterResourcesCalled == true {
		t.Errorf("ScanClusterWideResources should have not been called")
	}
}

func TestStartScannerForAllNamespaces(t *testing.T) {
	mockScanner := mockScanner{}

	// analogous to passing no flags
	err := startScanner("", false, &mockScanner)
	if err != nil {
		t.Errorf("err should be nil, but got %s", err.Error())
	}
	if mockScanner.scanNamespaceCalledWith != "" {
		t.Errorf("scanNamespace should have not been called")
	}
	if mockScanner.scanAllNamespacesCalled != true {
		t.Errorf("scanAllNamespaces not called")
	}
	if mockScanner.scanClusterResourcesCalled != true {
		t.Errorf("scanClusterWideResources not called")
	}
}

func TestScanClusterResources(t *testing.T) {
	mockScanner := mockScanner{}

	err := startScanner("", true, &mockScanner)
	if err != nil {
		t.Errorf("err should be nil, but got %s", err.Error())
	}
	if mockScanner.scanNamespaceCalledWith != "" {
		t.Errorf("scanNamespace should have not been called")
	}
	if mockScanner.scanAllNamespacesCalled == true {
		t.Errorf("scanAllNamespaces should have not been called")
	}

	if mockScanner.scanClusterResourcesCalled == false {
		t.Errorf("ScanClusterWideResources not called")
	}
}

type mockScanner struct {
	scanNamespaceCalledWith    string
	scanAllNamespacesCalled    bool
	scanClusterResourcesCalled bool
}

func (s *mockScanner) ScanNamespace(namespace string) error {
	s.scanNamespaceCalledWith = namespace
	return nil
}

func (s *mockScanner) ScanAllNamespaces() error {
	s.scanAllNamespacesCalled = true
	return nil
}

func (s *mockScanner) ScanClusterWideResources() error {
	s.scanClusterResourcesCalled = true
	return nil
}
