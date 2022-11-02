package cmd

import "testing"

func TestStartScannerForANamespace(t *testing.T) {
	const namespace = "default"
	mockScanner := mockScanner{}

	err := startScanner(namespace, &mockScanner)

	if err != nil {
		t.Errorf("err should be nil, but got %s", err.Error())
	}
	if mockScanner.scanNamespaceCalledWith != namespace {
		t.Errorf("scanNamespace should have been called with %s, but got %s", namespace, mockScanner.scanNamespaceCalledWith)
	}
	if mockScanner.scanAllNamespacesCalled == true {
		t.Errorf("scanAllNamespaces should have not been called")
	}
}

func TestStartScannerForAllNamespaces(t *testing.T) {
	const namespace = ""
	mockScanner := mockScanner{}

	err := startScanner(namespace, &mockScanner)

	if err != nil {
		t.Errorf("err should be nil, but got %s", err.Error())
	}
	if mockScanner.scanNamespaceCalledWith != "" {
		t.Errorf("scanNamespace should have not been called")
	}
	if mockScanner.scanAllNamespacesCalled != true {
		t.Errorf("scanAllNamespaces not called")
	}
}

type mockScanner struct {
	scanNamespaceCalledWith string
	scanAllNamespacesCalled bool
}

func (s *mockScanner) ScanNamespace(namespace string) error {
	s.scanNamespaceCalledWith = namespace
	return nil
}

func (s *mockScanner) ScanAllNamespaces() error {
	s.scanAllNamespacesCalled = true
	return nil
}
