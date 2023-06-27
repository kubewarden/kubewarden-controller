package v1

import (
	"testing"
)

func TestAdmissionPolicyGetContextAwareResources(t *testing.T) {
	c := AdmissionPolicy{}
	if len(c.GetContextAwareResources()) != 0 {
		t.Errorf("Context aware resources for namespaced policies should be empty")
	}
}
