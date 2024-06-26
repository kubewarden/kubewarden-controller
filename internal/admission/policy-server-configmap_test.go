package admission

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
)

func TestCreatePoliciesMap(t *testing.T) {
	_, validationPolicy, mutatingPolicy, contextAwarePolicy := createReconciler()

	var policies PolicyConfigEntryMap
	clusterAdmissionPolicies := []policiesv1.Policy{}
	policies = buildPoliciesMap(clusterAdmissionPolicies)
	if len(policies) != 0 {
		t.Error("Empty ClusterAdmissionPolicyList should generate empty policies map")
	}

	clusterAdmissionPolicies = []policiesv1.Policy{&validationPolicy, &mutatingPolicy, &contextAwarePolicy}
	policies = buildPoliciesMap(clusterAdmissionPolicies)
	if len(policies) != 3 {
		t.Error("Policy map must has 3 entries")
	}
	expectedPolicies := make(PolicyConfigEntryMap)
	expectedPolicies[validationPolicy.GetUniqueName()] = PolicyServerConfigEntry{
		NamespacedName: types.NamespacedName{
			Name: validationPolicy.GetName(),
		},
		URL:             "registry://blabla/validation-policy:latest",
		AllowedToMutate: false,
		Settings:        runtime.RawExtension{},
	}
	expectedPolicies[mutatingPolicy.GetUniqueName()] = PolicyServerConfigEntry{
		NamespacedName: types.NamespacedName{
			Name: mutatingPolicy.GetName(),
		},
		URL:             "registry://blabla/mutation-policy:latest",
		AllowedToMutate: true,
		Settings:        runtime.RawExtension{},
	}
	expectedPolicies[contextAwarePolicy.GetUniqueName()] = PolicyServerConfigEntry{
		NamespacedName: types.NamespacedName{
			Name: contextAwarePolicy.GetName(),
		},
		URL:             "registry://blabla/context-aware-policy:latest",
		AllowedToMutate: false,
		Settings:        runtime.RawExtension{},
		ContextAwareResources: []policiesv1.ContextAwareResource{
			{
				APIVersion: "v1",
				Kind:       "Pods",
			},
		},
	}
	if len(policies) != len(expectedPolicies) {
		t.Errorf("Policies maps must be length %d", len(expectedPolicies))
	}
	for policyName, policy := range policies {
		if expectedPolicy, ok := expectedPolicies[policyName]; !ok || !reflect.DeepEqual(expectedPolicy, policy) {
			t.Errorf("Policies map is missing some policy or the policies values are different from the expected.\n  Expected: %#v\n  Actual: %#v", expectedPolicy, policy)
		}
	}
}
