package client

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
)

func TestFindNamespacesForAllClusterAdmissionPolicies(t *testing.T) {
	// default, kubewarden and test namespaces are the only namespaces available in the mock test client

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
		expect   NamespacePolicies
	}{
		{"policy available in all ns", []k8sClient.Object{&allNs}, map[string][]policiesv1.Policy{"default": {&allNs}, "test": {&allNs}, "kubewarden": {&allNs}}},
		{"policy available in test ns", []k8sClient.Object{&testNs}, map[string][]policiesv1.Policy{"test": {&testNs}}},
		{"policies available in all ns and in test ns", []k8sClient.Object{&allNs, &testNs}, map[string][]policiesv1.Policy{"default": {&allNs}, "test": {&allNs, &testNs}, "kubewarden": {&allNs}}},
		{"no policies availables", []k8sClient.Object{}, map[string][]policiesv1.Policy{}},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			c := client{k8sClient: mockClient(ttest.policies...)}
			ns, err := c.findNamespacesForAllClusterAdmissionPolicies()
			if err != nil {
				t.Errorf("error should be nil:  %s", err.Error())
			}
			if !cmp.Equal(ns, ttest.expect) {
				t.Errorf("expected %v, but got %v", ttest.expect, ns)
			}
		})
	}
}

func TestFindNamespacesForClusterAdmissionPolicy(t *testing.T) {
	// default, kubewarden and test namespaces are the only namespaces available in the mock test client

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
			c := client{k8sClient: mockClient(&ttest.p)}
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
			c := client{k8sClient: mockClient(ttest.policies...)}
			policies, err := c.GetPoliciesForANamespace(ttest.namespace)
			if err != nil {
				t.Errorf("error should be nil:  %s", err.Error())
			}
			if !cmp.Equal(policies, ttest.expect, policySorter, policyComparer) {
				t.Errorf("expected %v, but got %v", ttest.expect, policies)
			}
		})
	}
}

func TestCreateOrAppendPolicyIfExist(t *testing.T) {
	p1 := &policiesv1.ClusterAdmissionPolicy{}
	p2 := &policiesv1.ClusterAdmissionPolicy{}

	tests := []struct {
		name   string
		np     NamespacePolicies
		ns     string
		p      policiesv1.Policy
		expect NamespacePolicies
	}{
		{"init if ns doesn't exist", make(NamespacePolicies), "test", p1, NamespacePolicies{"test": []policiesv1.Policy{p1}}},
		{"appends if exists", NamespacePolicies{"test": []policiesv1.Policy{p1}}, "test", p2, NamespacePolicies{"test": []policiesv1.Policy{p1, p2}}},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			createOrAppendPoliciesIfExist(ttest.np, ttest.ns, ttest.p)
			if !cmp.Equal(ttest.np, ttest.expect) {
				t.Errorf("expected %v, but got %v", ttest.expect, ttest.np)
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

func mockClient(initObjs ...k8sClient.Object) k8sClient.Client {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion}, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion})
	initObjs = append(initObjs, &nsDefault)
	initObjs = append(initObjs, &nsTest)
	initObjs = append(initObjs, &nsKubewarden)

	return fake.NewClientBuilder().WithScheme(customScheme).WithObjects(initObjs...).Build()
}
