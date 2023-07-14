package policies

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFindNamespacesForAllClusterAdmissionPolicies(t *testing.T) {
	// default, kubewarden and test namespaces are the only namespaces available in the mock test Fetcher

	// this policy evaluates resources in all namespaces
	allNs := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "all-namespaces",
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec:        policiesv1.PolicySpec{},
			NamespaceSelector: &metav1.LabelSelector{},
		},
	}

	// this policy evaluates resources just in the test namespace
	testNs := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-namespace",
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "test"},
			},
		}}

	tests := []struct {
		name     string
		policies []k8sClient.Object
		expect   map[string][]policiesv1.Policy
	}{
		{"policy available in all ns", []k8sClient.Object{&allNs}, map[string][]policiesv1.Policy{"default": {&allNs}, "test": {&allNs}, "kubewarden": {}}},
		{"policy available in test ns", []k8sClient.Object{&testNs}, map[string][]policiesv1.Policy{"test": {&testNs}, "default": {}, "kubewarden": {}}},
		{"policies available in all ns and in test ns", []k8sClient.Object{&allNs, &testNs}, map[string][]policiesv1.Policy{"default": {&allNs}, "test": {&allNs, &testNs}, "kubewarden": {}}},
		{"policy available in kubewarden space get always skipped", []k8sClient.Object{&allNs}, map[string][]policiesv1.Policy{"default": {&allNs}, "test": {&allNs}, "kubewarden": {}}},
		{"no policies availables", []k8sClient.Object{}, map[string][]policiesv1.Policy{"default": {}, "test": {}, "kubewarden": {}}},
	}

	policyComparer := cmp.Comparer(func(n, p policiesv1.Policy) bool { return p.GetUniqueName() == n.GetUniqueName() })
	policySorter := cmpopts.SortSlices(func(n, p policiesv1.Policy) bool { return p.GetUniqueName() > n.GetUniqueName() })

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			c := Fetcher{client: mockClient(ttest.policies...), kubewardenNamespace: "kubewarden"}
			ns, err := c.findNamespacesForAllClusterAdmissionPolicies()
			if err != nil {
				t.Errorf("error should be nil:  %s", err.Error())
			}
			if !cmp.Equal(ns, ttest.expect, policySorter, policyComparer) {
				t.Errorf("expected %v, but got %v", ttest.expect, ns)
			}
		})
	}
}

func TestFindNamespacesForClusterAdmissionPolicy(t *testing.T) {
	// default, kubewarden and test namespaces are the only namespaces available in the mock test Fetcher

	// this policy evaluates resources in all namespaces
	allNs := policiesv1.ClusterAdmissionPolicy{Spec: policiesv1.ClusterAdmissionPolicySpec{
		PolicySpec:        policiesv1.PolicySpec{},
		NamespaceSelector: &metav1.LabelSelector{},
	}}

	// this policy evaluates resources just in the test namespace
	testNs := policiesv1.ClusterAdmissionPolicy{Spec: policiesv1.ClusterAdmissionPolicySpec{
		PolicySpec: policiesv1.PolicySpec{},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		},
	}}

	// this policy doesn't evaluate resources in any namespace
	noMatchesMultipleSelector := policiesv1.ClusterAdmissionPolicy{Spec: policiesv1.ClusterAdmissionPolicySpec{
		PolicySpec: policiesv1.PolicySpec{},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "test"},
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: "NotIn",
				Values:   []string{"test"},
			}},
		},
	}}

	// this policy doesn't evaluate resources in any namespace
	noMatchesSelector := policiesv1.ClusterAdmissionPolicy{Spec: policiesv1.ClusterAdmissionPolicySpec{
		PolicySpec: policiesv1.PolicySpec{},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "test"},
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: "In",
				Values:   []string{"prod"},
			}},
		},
	}}

	// this policy evaluates resources in all namespaces except default
	noDefaultNs := policiesv1.ClusterAdmissionPolicy{Spec: policiesv1.ClusterAdmissionPolicySpec{
		PolicySpec: policiesv1.PolicySpec{},
		NamespaceSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: "NotIn",
				Values:   []string{"default"},
			}},
		},
	}}

	nsComparer := cmp.Comparer(func(n, p v1.Namespace) bool { return n.Name == p.Name })
	nsSorter := cmpopts.SortSlices(func(n, p v1.Namespace) bool { return n.Name < p.Name })

	tests := []struct {
		name   string
		p      policiesv1.ClusterAdmissionPolicy
		expect []v1.Namespace
	}{
		{"all namespaces present when there is no namespaceSelector", allNs, []v1.Namespace{nsTest, nsKubewarden, nsDefault}},
		{"just test ns is present", testNs, []v1.Namespace{nsTest}},
		{"no default ns is present", noDefaultNs, []v1.Namespace{nsTest, nsKubewarden}},
		{"no matching selector", noMatchesSelector, []v1.Namespace{}},
		{"no matching multiple selector", noMatchesMultipleSelector, []v1.Namespace{}},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			c := Fetcher{client: mockClient(&ttest.p)}
			namespaces, err := c.findNamespacesForClusterAdmissionPolicy(ttest.p)
			if err != nil {
				t.Errorf("error should be nil:  %s", err.Error())
			}
			if !cmp.Equal(namespaces, ttest.expect, nsComparer, nsSorter) {
				t.Errorf("expected %v, but got %v", ttest.expect, namespaces)
			}
		})
	}
}

func TestGetPoliciesForANamespace(t *testing.T) {
	mockFilter := func(policies []policiesv1.Policy) []policiesv1.Policy {
		return policies
	}
	// this policy evaluates resources in all namespaces
	allNsClusterPolicy := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "all-namespaces",
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec:        policiesv1.PolicySpec{},
			NamespaceSelector: &metav1.LabelSelector{},
		},
	}
	defaultPolicy := policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-policy",
			Namespace: "default",
		},
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{},
		},
	}
	testPolicy := policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "test",
		},
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{},
		},
	}

	policyComparer := cmp.Comparer(func(n, p policiesv1.Policy) bool { return p.GetUniqueName() == n.GetUniqueName() })
	policySorter := cmpopts.SortSlices(func(n, p policiesv1.Policy) bool { return p.GetUniqueName() > n.GetUniqueName() })

	tests := []struct {
		name      string
		namespace string
		policies  []k8sClient.Object
		expect    []policiesv1.Policy
	}{
		{"get policies in default ns", "default", []k8sClient.Object{&allNsClusterPolicy, &defaultPolicy, &testPolicy}, []policiesv1.Policy{&allNsClusterPolicy, &defaultPolicy}},
		{"get policies in test ns", "test", []k8sClient.Object{&allNsClusterPolicy, &defaultPolicy, &testPolicy}, []policiesv1.Policy{&allNsClusterPolicy, &testPolicy}},
		{"get policies in kubewarden ns", "kubewarden", []k8sClient.Object{&allNsClusterPolicy, &defaultPolicy, &testPolicy}, []policiesv1.Policy{&allNsClusterPolicy}},
		{"get policies in default ns with just AdmissionPolicy", "default", []k8sClient.Object{&defaultPolicy}, []policiesv1.Policy{&defaultPolicy}},
		{"get policies in default ns with just ClusterAdmissionPolicy", "default", []k8sClient.Object{&allNsClusterPolicy}, []policiesv1.Policy{&allNsClusterPolicy}},
		{"get policies when there is no policies", "default", []k8sClient.Object{}, []policiesv1.Policy{}},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			c := Fetcher{client: mockClient(ttest.policies...), filter: mockFilter}
			policies, _, err := c.GetPoliciesForANamespace(ttest.namespace) // we don't test for skippedNum, as with mockFilter it is always 0
			if err != nil {
				t.Errorf("error should be nil:  %s", err.Error())
			}
			if !cmp.Equal(policies, ttest.expect, policySorter, policyComparer) {
				t.Errorf("expected %v, but got %v", ttest.expect, policies)
			}
		})
	}
}

func TestGetClusterAdmissionPolicies(t *testing.T) {
	clusterPolicy1 := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cap1",
			// It's necessary to define ResourceVersion and Generation
			// because the fake client can set values for these fields.
			// See more at docs:
			// ObjectMeta's `Generation` and `ResourceVersion` don't
			// behave properly, Patch or Update operations that rely
			// on these fields will fail, or give false positives.
			// https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/client/fake
			ResourceVersion: "123",
			Generation:      1,
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"", "apps"},
						APIVersions: []string{"v1", "alphav1"},
						Resources:   []string{"pods", "deployments"},
					},
				},
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: policiesv1.PolicyStatusActive,
		},
	}

	clusterPolicy2 := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cap2",
			// It's necessary to define ResourceVersion and Generation
			// because the fake client can set values for these fields.
			// See more at docs:
			// ObjectMeta's `Generation` and `ResourceVersion` don't
			// behave properly, Patch or Update operations that rely
			// on these fields will fail, or give false positives.
			// https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/client/fake
			ResourceVersion: "123",
			Generation:      1,
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: true,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"", "apps"},
						APIVersions: []string{"v1", "alphav1"},
						Resources:   []string{"pods", "deployments"},
					},
				},
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: policiesv1.PolicyStatusActive,
		},
	}
	clusterPolicy3 := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cap3",
			// It's necessary to define ResourceVersion and Generation
			// because the fake client can set values for these fields.
			// See more at docs:
			// ObjectMeta's `Generation` and `ResourceVersion` don't
			// behave properly, Patch or Update operations that rely
			// on these fields will fail, or give false positives.
			// https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/client/fake
			ResourceVersion: "123",
			Generation:      1,
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				BackgroundAudit: false,
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"", "apps"},
						APIVersions: []string{"v1", "alphav1"},
						Resources:   []string{"pods", "deployments"},
					},
				},
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: policiesv1.PolicyStatusPending,
		},
	}

	tests := []struct {
		name                  string
		policies              []k8sClient.Object
		expect                []policiesv1.Policy
		expectSkippedPolicies int
	}{
		{"Get all ClusterAdmissionPolicies", []k8sClient.Object{&clusterPolicy1, &clusterPolicy2}, []policiesv1.Policy{&clusterPolicy1, &clusterPolicy2}, 0},
		{"Get only auditable ClusterAdmissionPolicies", []k8sClient.Object{&clusterPolicy1, &clusterPolicy2, &clusterPolicy3}, []policiesv1.Policy{&clusterPolicy1, &clusterPolicy2}, 1},
	}

	policyComparer := cmp.Comparer(func(n, p policiesv1.Policy) bool { return p.GetUniqueName() == n.GetUniqueName() })
	policySorter := cmpopts.SortSlices(func(n, p policiesv1.Policy) bool { return p.GetUniqueName() > n.GetUniqueName() })

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			fetcher := Fetcher{client: mockClient(ttest.policies...), filter: filterAuditablePolicies}

			policies, skippedPolicies, err := fetcher.GetClusterAdmissionPolicies()
			if err != nil {
				t.Errorf("error should be nil:  %s", err.Error())
			}
			if !cmp.Equal(policies, ttest.expect, policySorter, policyComparer) {
				diff := cmp.Diff(ttest.expect, policies)
				t.Errorf("ClusterAdmissionPolicy list does not match the expected values: %s", diff)
			}
			if skippedPolicies != ttest.expectSkippedPolicies {
				t.Errorf("expected skipped policies count: %d. Got %d", ttest.expectSkippedPolicies, skippedPolicies)
			}
		})
	}
}

var nsDefault = v1.Namespace{
	ObjectMeta: metav1.ObjectMeta{
		Name:   "default",
		Labels: map[string]string{"kubernetes.io/metadata.name": "default"},
	},
}
var nsTest = v1.Namespace{
	ObjectMeta: metav1.ObjectMeta{
		Name:   "test",
		Labels: map[string]string{"kubernetes.io/metadata.name": "test", "env": "test"},
	},
}
var nsKubewarden = v1.Namespace{
	ObjectMeta: metav1.ObjectMeta{
		Name:   "kubewarden",
		Labels: map[string]string{"kubernetes.io/metadata.name": "kubewarden"},
	},
}

func mockClient(initObjs ...k8sClient.Object) k8sClient.Client { //nolint:ireturn
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: constants.KubewardenPoliciesGroup, Version: constants.KubewardenPoliciesVersion}, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, schema.GroupVersion{Group: constants.KubewardenPoliciesGroup, Version: constants.KubewardenPoliciesVersion})
	initObjs = append(initObjs, &nsDefault)
	initObjs = append(initObjs, &nsTest)
	initObjs = append(initObjs, &nsKubewarden)

	return fake.NewClientBuilder().WithScheme(customScheme).WithObjects(initObjs...).Build()
}
