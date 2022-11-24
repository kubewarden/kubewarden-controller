package resources

import (
	"github.com/google/go-cmp/cmp"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"testing"
)

func TestFindGVRMap(t *testing.T) {
	// policies for testing
	p1 := policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
			Rules: []admissionregistrationv1.RuleWithOperations{admissionregistrationv1.RuleWithOperations{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"pods"},
				},
			},
			},
		}},
	}

	p2 := policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
			Rules: []admissionregistrationv1.RuleWithOperations{admissionregistrationv1.RuleWithOperations{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"", "apps"},
					APIVersions: []string{"v1", "alphav1"},
					Resources:   []string{"pods", "deployments"},
				},
			},
			},
		}},
	}

	p3 := policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
			Rules: []admissionregistrationv1.RuleWithOperations{admissionregistrationv1.RuleWithOperations{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"", "apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"pods", "deployments"},
				},
			},
			},
		}},
	}

	// all posible combination of GVR (Group, Version, Resource) for p1, p2 and p3
	gvr1 := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}
	gvr2 := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "deployments",
	}
	gvr3 := schema.GroupVersionResource{
		Group:    "",
		Version:  "alphav1",
		Resource: "pods",
	}
	gvr4 := schema.GroupVersionResource{
		Group:    "",
		Version:  "alphav1",
		Resource: "deployments",
	}
	gvr5 := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "pods",
	}
	gvr6 := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "deployments",
	}
	gvr7 := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "alphav1",
		Resource: "pods",
	}
	gvr8 := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "alphav1",
		Resource: "deployments",
	}

	// expected outcome

	expectedP1andP2 := make(map[schema.GroupVersionResource][]policiesv1.Policy)

	expectedP1andP2[gvr1] = []policiesv1.Policy{&p1, &p2}
	expectedP1andP2[gvr2] = []policiesv1.Policy{&p2}
	expectedP1andP2[gvr3] = []policiesv1.Policy{&p2}
	expectedP1andP2[gvr4] = []policiesv1.Policy{&p2}
	expectedP1andP2[gvr5] = []policiesv1.Policy{&p2}
	expectedP1andP2[gvr6] = []policiesv1.Policy{&p2}
	expectedP1andP2[gvr7] = []policiesv1.Policy{&p2}
	expectedP1andP2[gvr8] = []policiesv1.Policy{&p2}

	expectedP1P2andP3 := make(map[schema.GroupVersionResource][]policiesv1.Policy)

	expectedP1P2andP3[gvr1] = []policiesv1.Policy{&p1, &p2, &p3}
	expectedP1P2andP3[gvr2] = []policiesv1.Policy{&p2, &p3}
	expectedP1P2andP3[gvr3] = []policiesv1.Policy{&p2}
	expectedP1P2andP3[gvr4] = []policiesv1.Policy{&p2}
	expectedP1P2andP3[gvr5] = []policiesv1.Policy{&p2, &p3}
	expectedP1P2andP3[gvr6] = []policiesv1.Policy{&p2, &p3}
	expectedP1P2andP3[gvr7] = []policiesv1.Policy{&p2}
	expectedP1P2andP3[gvr8] = []policiesv1.Policy{&p2}

	expectedP1andP3 := make(map[schema.GroupVersionResource][]policiesv1.Policy)

	expectedP1andP3[gvr1] = []policiesv1.Policy{&p1, &p3}
	expectedP1andP3[gvr2] = []policiesv1.Policy{&p3}
	expectedP1andP3[gvr5] = []policiesv1.Policy{&p3}
	expectedP1andP3[gvr6] = []policiesv1.Policy{&p3}

	expectedP1 := make(map[schema.GroupVersionResource][]policiesv1.Policy)

	expectedP1[gvr1] = []policiesv1.Policy{&p1}

	tests := []struct {
		name     string
		policies []policiesv1.Policy
		expect   map[schema.GroupVersionResource][]policiesv1.Policy
	}{
		{"policy1 (just pods) and policy2 (pods, deployments, v1 and alphav1)", []policiesv1.Policy{&p1, &p2}, expectedP1andP2},
		{"policy1 (just pods), policy2 (pods, deployments, v1 and alphav1) and policy3 (pods, deployments, v1)", []policiesv1.Policy{&p1, &p2, &p3}, expectedP1P2andP3},
		{"policy1 (just pods) and policy3 (pods, deployments, v1)", []policiesv1.Policy{&p1, &p3}, expectedP1andP3},
		{"policy1 (just pods)", []policiesv1.Policy{&p1}, expectedP1},
		{"empty array", []policiesv1.Policy{}, make(map[schema.GroupVersionResource][]policiesv1.Policy)},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			if !cmp.Equal(createGVRPolicyMap(ttest.policies), ttest.expect) {
				t.Errorf("expected %v, but got %v", ttest.expect, createGVRPolicyMap(ttest.policies))
			}
		})
	}

}
