package v1

import (
	"testing"
)

func TestClusterAdmissionPolicyGetContextAwareResources(t *testing.T) {
	policy := ClusterAdmissionPolicy{
		Spec: ClusterAdmissionPolicySpec{
			ContextAwareResources: []ContextAwareResource{
				{
					APIVersion: "v1",
					Kind:       "Pods",
				},
			},
		},
	}
	if len(policy.GetContextAwareResources()) != 1 {
		t.Fatal("Missing context aware resources definition")
	}

	if policy.GetContextAwareResources()[0].APIVersion != "v1" {
		t.Errorf("Invalid context aware resource APIVersion")
	}

	if policy.GetContextAwareResources()[0].Kind != "Pods" {
		t.Errorf("Invalid context aware resource kind")
	}
}
