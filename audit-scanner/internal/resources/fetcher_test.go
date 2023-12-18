package resources

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"

	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	fakekubernetes "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	clienttesting "k8s.io/client-go/testing"
)

// policies for testing

var policy1 = policiesv1.AdmissionPolicy{
	Spec: policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
		Rules: []admissionregistrationv1.RuleWithOperations{
			{
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

// used to test incorrect or unknown GVKs
var policy2 = policiesv1.ClusterAdmissionPolicy{
	Spec: policiesv1.ClusterAdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
		Rules: []admissionregistrationv1.RuleWithOperations{
			{
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

var policy3 = policiesv1.AdmissionPolicy{
	Spec: policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
		Rules: []admissionregistrationv1.RuleWithOperations{
			{
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

var policy4 = policiesv1.AdmissionPolicy{
	Spec: policiesv1.AdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Operations: nil,
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
			},
		}},
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"testing": "label"},
		},
	}},
}

// used to test incorrect or unknown GVKs
var policyIncorrectRules = policiesv1.ClusterAdmissionPolicy{
	Spec: policiesv1.ClusterAdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
		Rules: []admissionregistrationv1.RuleWithOperations{
			{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"pods", "Unexistent"},
				},
			},
		},
	}},
}

// used to test skipping of clusterwide resources
var policyPodsNamespaces = policiesv1.ClusterAdmissionPolicy{
	Spec: policiesv1.ClusterAdmissionPolicySpec{PolicySpec: policiesv1.PolicySpec{
		Rules: []admissionregistrationv1.RuleWithOperations{
			{
				Operations: nil,
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"pods", "namespaces"},
				},
			},
		},
	}},
}

func TestGetResourcesForPolicies(t *testing.T) {
	pod1 := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podDefault",
			Namespace: "default",
		},
		Spec: v1.PodSpec{},
	}
	pod2 := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podKubewarden",
			Namespace: "kubewarden",
		},
		Spec: v1.PodSpec{},
	}
	pod3 := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podKubewarden2",
			Namespace: "kubewarden",
			Labels:    map[string]string{"testing": "label"},
		},
		Spec: v1.PodSpec{},
	}
	deployment1 := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deploymentDefault",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{},
	}
	namespace1 := v1.Namespace{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-namespace",
		},
	}
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(policiesv1.GroupVersion, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, policiesv1.GroupVersion)

	dynamicClient := fake.NewSimpleDynamicClient(customScheme, &policy1, &pod1, &pod2, &pod3, &deployment1, &namespace1)

	apiResourceList := metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{
				Name:         "namespaces",
				SingularName: "namespace",
				Kind:         "Namespace",
				Namespaced:   false,
			},
			{
				Name:         "pods",
				SingularName: "pod",
				Kind:         "Pod",
				Namespaced:   true,
			},
		},
	}
	fakeClientSet := fakekubernetes.NewSimpleClientset()
	fakeClientSet.Resources = []*metav1.APIResourceList{&apiResourceList}

	unstructuredPod1 := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":              "podDefault",
			"namespace":         "default",
			"creationTimestamp": nil,
		},
		"spec": map[string]interface{}{
			"containers": nil,
		},
		"status": map[string]interface{}{},
	}
	unstructuredPod3 := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "podKubewarden2",
			"namespace": "kubewarden",
			"labels": map[string]interface{}{
				"testing": "label",
			},
			"creationTimestamp": nil,
		},
		"spec": map[string]interface{}{
			"containers": nil,
		},
		"status": map[string]interface{}{},
	}

	expectedP1 := []AuditableResources{{
		Policies:  []policiesv1.Policy{&policy1},
		Resources: []unstructured.Unstructured{{Object: unstructuredPod1}},
	}}

	expectedP4 := []AuditableResources{{
		Policies:  []policiesv1.Policy{&policy4},
		Resources: []unstructured.Unstructured{{Object: unstructuredPod3}},
	}}

	expectedPIncorrectRules := []AuditableResources{{
		Policies:  []policiesv1.Policy{&policyIncorrectRules},
		Resources: []unstructured.Unstructured{{Object: unstructuredPod1}},
		// note that the resource "Unexistent" is correctly missing here
	}}

	expectedPPodsNamespaces := []AuditableResources{{
		Policies:  []policiesv1.Policy{&policyPodsNamespaces},
		Resources: []unstructured.Unstructured{{Object: unstructuredPod1}},
		// note that the namespacej resource is correctly missing here
	}}

	fetcher := Fetcher{dynamicClient, "", "", fakeClientSet}

	tests := []struct {
		name      string
		policies  []policiesv1.Policy
		expect    []AuditableResources
		namespace string
	}{
		{"policy1 (just pods)", []policiesv1.Policy{&policy1}, expectedP1, "default"},
		{"no policies", []policiesv1.Policy{}, []AuditableResources{}, "default"},
		{"policy with label filter", []policiesv1.Policy{&policy4}, expectedP4, "kubewarden"},
		{"we skip incorrect GVKs", []policiesv1.Policy{&policyIncorrectRules}, expectedPIncorrectRules, "default"},
		{"we skip clusterwide resources", []policiesv1.Policy{&policyPodsNamespaces}, expectedPPodsNamespaces, "default"}, // namespaces get filtered
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			resources, err := fetcher.GetResourcesForPolicies(context.Background(), ttest.policies, ttest.namespace)
			if err != nil {
				t.Errorf("error shouldn't have happened " + err.Error())
			}
			if !cmp.Equal(resources, ttest.expect) {
				diff := cmp.Diff(ttest.expect, resources)
				t.Errorf("Invalid resources: %s", diff)
			}
		})
	}
}

func TestCreateGVRPolicyMap(t *testing.T) {
	// all posible combination of GVR (Group, Version, Resource) for p1, p2 and p3
	gvr1 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		},
		objectSelector: nil,
	}
	gvr2 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "deployments",
		},
		objectSelector: nil,
	}
	gvr3 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "",
			Version:  "alphav1",
			Resource: "pods",
		}, objectSelector: nil,
	}
	gvr4 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "",
			Version:  "alphav1",
			Resource: "deployments",
		}, objectSelector: nil,
	}
	gvr5 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "apps",
			Version:  "v1",
			Resource: "pods",
		}, objectSelector: nil,
	}
	gvr6 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "apps",
			Version:  "v1",
			Resource: "deployments",
		}, objectSelector: nil,
	}
	gvr7 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "apps",
			Version:  "alphav1",
			Resource: "pods",
		}, objectSelector: nil,
	}
	gvr8 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "apps",
			Version:  "alphav1",
			Resource: "deployments",
		}, objectSelector: nil,
	}
	gvr9 := resourceFilter{
		groupVersionResource: schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		},
		objectSelector: policy4.Spec.ObjectSelector,
	}

	// expected outcome

	expectedP1andP2 := make(map[resourceFilter][]policiesv1.Policy)

	expectedP1andP2[gvr1] = []policiesv1.Policy{&policy1, &policy2}
	expectedP1andP2[gvr2] = []policiesv1.Policy{&policy2}
	expectedP1andP2[gvr3] = []policiesv1.Policy{&policy2}
	expectedP1andP2[gvr4] = []policiesv1.Policy{&policy2}
	expectedP1andP2[gvr5] = []policiesv1.Policy{&policy2}
	expectedP1andP2[gvr6] = []policiesv1.Policy{&policy2}
	expectedP1andP2[gvr7] = []policiesv1.Policy{&policy2}
	expectedP1andP2[gvr8] = []policiesv1.Policy{&policy2}

	expectedP1P2andP3 := make(map[resourceFilter][]policiesv1.Policy)

	expectedP1P2andP3[gvr1] = []policiesv1.Policy{&policy1, &policy2, &policy3}
	expectedP1P2andP3[gvr2] = []policiesv1.Policy{&policy2, &policy3}
	expectedP1P2andP3[gvr3] = []policiesv1.Policy{&policy2}
	expectedP1P2andP3[gvr4] = []policiesv1.Policy{&policy2}
	expectedP1P2andP3[gvr5] = []policiesv1.Policy{&policy2, &policy3}
	expectedP1P2andP3[gvr6] = []policiesv1.Policy{&policy2, &policy3}
	expectedP1P2andP3[gvr7] = []policiesv1.Policy{&policy2}
	expectedP1P2andP3[gvr8] = []policiesv1.Policy{&policy2}

	expectedP1andP3 := make(map[resourceFilter][]policiesv1.Policy)

	expectedP1andP3[gvr1] = []policiesv1.Policy{&policy1, &policy3}
	expectedP1andP3[gvr2] = []policiesv1.Policy{&policy3}
	expectedP1andP3[gvr5] = []policiesv1.Policy{&policy3}
	expectedP1andP3[gvr6] = []policiesv1.Policy{&policy3}

	expectedP1 := make(map[resourceFilter][]policiesv1.Policy)

	expectedP1[gvr1] = []policiesv1.Policy{&policy1}

	expectedP4 := make(map[resourceFilter][]policiesv1.Policy)
	expectedP4[gvr9] = []policiesv1.Policy{&policy4}

	tests := []struct {
		name     string
		policies []policiesv1.Policy
		expect   map[resourceFilter][]policiesv1.Policy
	}{
		{"policy1 (just pods) and policy2 (pods, deployments, v1 and alphav1)", []policiesv1.Policy{&policy1, &policy2}, expectedP1andP2},
		{"policy1 (just pods), policy2 (pods, deployments, v1 and alphav1) and policy3 (pods, deployments, v1)", []policiesv1.Policy{&policy1, &policy2, &policy3}, expectedP1P2andP3},
		{"policy1 (just pods) and policy3 (pods, deployments, v1)", []policiesv1.Policy{&policy1, &policy3}, expectedP1andP3},
		{"policy1 (just pods)", []policiesv1.Policy{&policy1}, expectedP1},
		{"empty array", []policiesv1.Policy{}, make(map[resourceFilter][]policiesv1.Policy)},
		{"with label filters", []policiesv1.Policy{&policy4}, expectedP4},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			gvrPolicyMap := createGVRPolicyMap(ttest.policies)
			if !cmp.Equal(gvrPolicyMap, ttest.expect) {
				diff := cmp.Diff(ttest.expect, gvrPolicyMap)
				t.Errorf("Invalid gvrPolicyMap: %s", diff)
			}
		})
	}
}

func TestGetPolicyServerByName(t *testing.T) {
	policyServerObj := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testing-name",
			Labels: map[string]string{
				"testing-label": "testing",
			},
		},
	}
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(policiesv1.GroupVersion, &policiesv1.PolicyServer{}, &policiesv1.PolicyServerList{})
	metav1.AddToGroupVersion(customScheme, policiesv1.GroupVersion)

	dynamicClient := fake.NewSimpleDynamicClient(customScheme, &policyServerObj)
	fetcher := Fetcher{dynamicClient, "", "", nil}

	policyServer, err := getPolicyServerByName(context.Background(), "testing-name", &fetcher.dynamicClient)
	if err != nil {
		t.Fatal("Cannot get policy server: ", err)
	}
	appLabel, ok := policyServer.GetLabels()["testing-label"]
	if !ok || appLabel != "testing" {
		t.Error("Policy server returned is not valid")
	}
	if policyServer.AppLabel() != "kubewarden-policy-server-testing-name" {
		t.Error("Unexpected Policy Server app label")
	}
}

func TestGetServiceByAppLabel(t *testing.T) {
	policyServerObj := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing-service",
			Namespace: "default",
			Labels: map[string]string{
				"app": "testing",
			},
		},
	}
	customScheme := scheme.Scheme

	dynamicClient := fake.NewSimpleDynamicClient(customScheme, &policyServerObj)
	fetcher := Fetcher{dynamicClient, "", "", nil}

	service, err := getServiceByAppLabel(context.Background(), "testing", "default", &fetcher.dynamicClient)
	if err != nil {
		t.Fatal("Cannot get service: ", err)
	}
	if service.Name != "testing-service" {
		t.Error("Service returned is not valid")
	}
}

func TestGetClusterWideResourcesForPolicies(t *testing.T) {
	pod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podDefault",
			Namespace: "default",
		},
		Spec: v1.PodSpec{},
	}
	namespace := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testingns",
		},
	}
	namespace2 := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testingns-with-label",
			Labels: map[string]string{
				"testing": "label",
			},
		},
	}
	policy := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cap",
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
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods", "namespaces"},
						},
					},
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: policiesv1.PolicyStatusActive,
		},
	}
	policyWithLabelFilter := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cap-with-label-filter",
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
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods", "namespaces"},
						},
					},
				},
				ObjectSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"testing": "label"},
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: policiesv1.PolicyStatusActive,
		},
	}

	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(policiesv1.GroupVersion, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	customScheme.AddKnownTypes(v1.SchemeGroupVersion, &namespace)
	metav1.AddToGroupVersion(customScheme, policiesv1.GroupVersion)

	dynamicClient := fake.NewSimpleDynamicClient(customScheme, &policy, &policyWithLabelFilter, &pod, &namespace, &namespace2)

	unstructuredNamespace := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]interface{}{
			"name":              "testingns",
			"creationTimestamp": nil,
		},
		"spec":   map[string]interface{}{},
		"status": map[string]interface{}{},
	}
	unstructuredNamespace2 := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]interface{}{
			"name":              "testingns-with-label",
			"creationTimestamp": nil,
			"labels": map[string]interface{}{
				"testing": "label",
			},
		},
		"spec":   map[string]interface{}{},
		"status": map[string]interface{}{},
	}

	apiResourceList := metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{
				Name:         "namespaces",
				SingularName: "namespace",
				Kind:         "Namespace",
				Namespaced:   false,
			},
			{
				Name:         "pods",
				SingularName: "pod",
				Kind:         "Pod",
				Namespaced:   true,
			},
		},
	}

	fakeClientSet := fakekubernetes.NewSimpleClientset()
	fakeClientSet.Resources = []*metav1.APIResourceList{&apiResourceList}

	fetcher := Fetcher{dynamicClient, "", "", fakeClientSet}

	tests := []struct {
		name             string
		policies         []policiesv1.Policy
		expectedResource []AuditableResources
	}{
		{"Filter cluster wide resource with no label filter", []policiesv1.Policy{&policy}, []AuditableResources{{
			Policies:  []policiesv1.Policy{&policy},
			Resources: []unstructured.Unstructured{{Object: unstructuredNamespace}, {Object: unstructuredNamespace2}},
		}}},
		{"Filter cluster wide resource with label filter", []policiesv1.Policy{&policyWithLabelFilter}, []AuditableResources{{
			Policies:  []policiesv1.Policy{&policyWithLabelFilter},
			Resources: []unstructured.Unstructured{{Object: unstructuredNamespace2}},
		}}},
	}

	for _, test := range tests {
		ttest := test
		t.Run(ttest.name, func(t *testing.T) {
			resources, err := fetcher.GetClusterWideResourcesForPolicies(context.Background(), ttest.policies)
			if err != nil {
				t.Errorf("unexpected error: " + err.Error())
			}
			if !cmp.Equal(resources, ttest.expectedResource) {
				diff := cmp.Diff(ttest.expectedResource, resources)
				t.Errorf("Expected AuditableResources differs from the expected value: %s", diff)
			}
		})
	}
}

func TestIsNamespacedResource(t *testing.T) {
	tests := []struct {
		name                 string
		apiResourceList      metav1.APIResourceList
		gvr                  schema.GroupVersionResource
		expectedIsNamespaced bool
		expectedErr          error
	}{
		{
			"pods",
			metav1.APIResourceList{
				GroupVersion: "v1",
				APIResources: []metav1.APIResource{
					{
						Name:         "namespaces",
						SingularName: "namespace",
						Kind:         "Namespace",
						Namespaced:   false,
					},
					{
						Name:         "pods",
						SingularName: "pod",
						Kind:         "Pod",
						Namespaced:   true,
					},
				},
			},
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			true, nil,
		},
		{
			"namespaces",
			metav1.APIResourceList{
				GroupVersion: "v1",
				APIResources: []metav1.APIResource{
					{
						Name:         "namespaces",
						SingularName: "namespace",
						Kind:         "Namespace",
						Namespaced:   false,
					},
					{
						Name:         "pods",
						SingularName: "pod",
						Kind:         "Pod",
						Namespaced:   true,
					},
				},
			},
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "namespaces",
			},
			false, nil,
		},
		{
			"resource not found",
			metav1.APIResourceList{
				GroupVersion: "v1",
				APIResources: []metav1.APIResource{
					{
						Name:         "namespaces",
						SingularName: "namespace",
						Kind:         "Namespace",
						Namespaced:   false,
					},
					{
						Name:         "pods",
						SingularName: "pod",
						Kind:         "Pod",
						Namespaced:   true,
					},
				},
			},
			schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "foos",
			},
			false, constants.ErrResourceNotFound,
		},
	}

	for _, ttest := range tests {
		ttest := ttest
		t.Run(ttest.name, func(t *testing.T) {
			customScheme := scheme.Scheme
			metav1.AddToGroupVersion(scheme.Scheme, policiesv1.GroupVersion)
			dynamicClient := fake.NewSimpleDynamicClient(customScheme)
			fakeClientSet := fakekubernetes.NewSimpleClientset()
			fakeClientSet.Resources = []*metav1.APIResourceList{&ttest.apiResourceList}
			fetcher := Fetcher{dynamicClient, "", "", fakeClientSet}

			isNamespaced, err := fetcher.isNamespacedResource(ttest.gvr)
			if (err != nil && ttest.expectedErr != nil && !errors.Is(err, ttest.expectedErr)) || (err != nil && ttest.expectedErr == nil) {
				t.Errorf("unexpected error: " + err.Error())
			}
			if isNamespaced != ttest.expectedIsNamespaced {
				t.Errorf("isNamespacedResource return expected to be %t, got %t", isNamespaced, ttest.expectedIsNamespaced)
			}
		})
	}
}

func TestLackOfPermsWhenGettingResources(t *testing.T) {
	pod1 := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podDefault",
			Namespace: "default",
		},
		Spec: v1.PodSpec{},
	}
	namespace1 := v1.Namespace{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-namespace",
		},
	}
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(policiesv1.GroupVersion, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, policiesv1.GroupVersion)

	dynamicClient := fake.NewSimpleDynamicClient(customScheme, &policy1, &pod1, &namespace1)
	// simulate lacking permissions when listing pods or namespaces. This should
	// make the filtering skip these resources, and produce no error
	dynamicClient.PrependReactor("list", "pods",
		func(action clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apimachineryerrors.NewForbidden(schema.GroupResource{
				Resource: "pods",
			}, "", errors.New("reason"))
		})
	dynamicClient.PrependReactor("list", "namespaces",
		func(action clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apimachineryerrors.NewForbidden(schema.GroupResource{
				Resource: "namespaces",
			}, "", errors.New("reason"))
		})

	apiResourceList := metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{
				Name:         "namespaces",
				SingularName: "namespace",
				Kind:         "Namespace",
				Namespaced:   false,
			},
			{
				Name:         "pods",
				SingularName: "pod",
				Kind:         "Pod",
				Namespaced:   true,
			},
		},
	}
	fakeClientSet := fakekubernetes.NewSimpleClientset()
	fakeClientSet.Resources = []*metav1.APIResourceList{&apiResourceList}

	// the pairs (policies,resources) should be empty, as (pods,namespaces) have
	// been skipped because of lack of permissions
	expectedP1 := []AuditableResources{}

	fetcher := Fetcher{dynamicClient, "", "", fakeClientSet}

	resources, err := fetcher.GetResourcesForPolicies(context.Background(), []policiesv1.Policy{&policy1}, "default")
	if err != nil {
		t.Errorf("error shouldn't have happened " + err.Error())
	}
	if !cmp.Equal(resources, expectedP1) {
		diff := cmp.Diff(expectedP1, resources)
		t.Errorf("Invalid resources: %s", diff)
	}

	resources, err = fetcher.GetClusterWideResourcesForPolicies(context.Background(), []policiesv1.Policy{&policy1})
	if err != nil {
		t.Errorf("error shouldn't have happened " + err.Error())
	}
	if !cmp.Equal(resources, expectedP1) {
		diff := cmp.Diff(expectedP1, resources)
		t.Errorf("Invalid resources: %s", diff)
	}
}
