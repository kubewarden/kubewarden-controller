package admission

import (
	"context"
	"testing"

	kubewardenv1 "github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetPolicies(t *testing.T) {
	const policyServer = "test"

	tests := []struct {
		name     string
		policies []client.Object
		expect   int
	}{
		{
			"empty lists",
			[]client.Object{},
			0,
		},
		{
			"with cluster and no namespaced policies",
			[]client.Object{
				&kubewardenv1.ClusterAdmissionPolicy{
					Spec: kubewardenv1.ClusterAdmissionPolicySpec{
						PolicySpec: kubewardenv1.PolicySpec{
							PolicyServer: policyServer,
						},
					},
				},
			},
			1,
		},
		{
			"with namespaced and no cluster policies",
			[]client.Object{
				&kubewardenv1.AdmissionPolicy{
					Spec: kubewardenv1.AdmissionPolicySpec{
						PolicySpec: kubewardenv1.PolicySpec{
							PolicyServer: policyServer,
						},
					},
				},
			},
			1,
		},
		{
			"with cluster and namespaced policies",
			[]client.Object{
				&kubewardenv1.ClusterAdmissionPolicy{
					Spec: kubewardenv1.ClusterAdmissionPolicySpec{
						PolicySpec: kubewardenv1.PolicySpec{
							PolicyServer: policyServer,
						},
					},
				},
				&kubewardenv1.AdmissionPolicy{
					Spec: kubewardenv1.AdmissionPolicySpec{
						PolicySpec: kubewardenv1.PolicySpec{
							PolicyServer: policyServer,
						},
					},
				},
			},
			2,
		},
	}
	for _, test := range tests {
		ttest := test // ensure ttest is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			reconciler := newReconciler(ttest.policies)
			policies, err := reconciler.GetPolicies(context.Background(), &kubewardenv1.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{Name: policyServer},
			}, IncludeDeleted)
			if err != nil {
				t.Errorf("received unexpected error %s", err.Error())
			}
			if len(policies) != ttest.expect {
				t.Errorf("expected %b, but got %b", ttest.expect, len(policies))
			}
		})
	}
}

func newReconciler(policies []client.Object) Reconciler {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: "policies.kubewarden.io", Version: "v1alpha2"}, &kubewardenv1.ClusterAdmissionPolicy{}, &kubewardenv1.AdmissionPolicy{}, &kubewardenv1.ClusterAdmissionPolicyList{}, &kubewardenv1.AdmissionPolicyList{})
	cl := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(policies...).Build()

	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}

func TestNamespaceSelectorGenerationAndNotSkipKubewardenNamesapce(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: false,
	}
	policy := &kubewardenv1.ClusterAdmissionPolicy{
		Spec: kubewardenv1.ClusterAdmissionPolicySpec{
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      constants.KubernetesNamespaceNameLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"somenamespace"},
				},
				},
			},
		},
	}
	namespaceSelector := reconciler.webhookNamespaceSelector(policy)
	if namespaceSelector.MatchExpressions[0].Key != constants.KubernetesNamespaceNameLabel {
		t.Error("Namespace selector key should not change")
	}
	if namespaceSelector.MatchExpressions[0].Operator != metav1.LabelSelectorOpNotIn {
		t.Error("Namespace selector operator should not change")
	}
	if len(namespaceSelector.MatchExpressions[0].Values) != 1 || namespaceSelector.MatchExpressions[0].Values[0] != "somenamespace" {
		t.Error("Namespace selector values should not change")
	}
}

func TestNamespaceSelectorGeneration(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: true,
	}
	policy := &kubewardenv1.ClusterAdmissionPolicy{
		Spec: kubewardenv1.ClusterAdmissionPolicySpec{
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      constants.KubernetesNamespaceNameLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"somenamespace"},
				},
				},
			},
		},
	}
	namespaceSelector := reconciler.webhookNamespaceSelector(policy)
	if len(namespaceSelector.MatchExpressions) != 2 {
		t.Errorf("Namespace selector should have only the previous selectors and another one to skip Kuberwarden namespace. Selectors found: %d", len(namespaceSelector.MatchExpressions))
		return
	}
	if namespaceSelector.MatchExpressions[0].Key != constants.KubernetesNamespaceNameLabel {
		t.Error("Namespace selector key should not change")
	}
	if namespaceSelector.MatchExpressions[0].Operator != metav1.LabelSelectorOpNotIn {
		t.Error("Namespace selector operator should not change")
	}
	if len(namespaceSelector.MatchExpressions[0].Values) != 1 || namespaceSelector.MatchExpressions[0].Values[0] != "somenamespace" {
		t.Error("Namespace selector values should not change")
	}
	if namespaceSelector.MatchExpressions[1].Key != constants.KubernetesNamespaceNameLabel {
		t.Error("Selector to skip Kuberwarden namespace has invalid key")
	}
	if namespaceSelector.MatchExpressions[1].Operator != metav1.LabelSelectorOpNotIn {
		t.Error("Selector to skip Kuberwarden namespace has invalid operator")
	}
	if len(namespaceSelector.MatchExpressions[1].Values) != 1 || namespaceSelector.MatchExpressions[1].Values[0] != "kubewarden" {
		t.Error("Selector to skip Kuberwarden namespace has invalid namespace")
	}
}

func TestNamespaceSelectorGenerationWithNilPolicyNamespaceSelector(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: false,
	}
	policy := &kubewardenv1.ClusterAdmissionPolicy{
		Spec: kubewardenv1.ClusterAdmissionPolicySpec{},
	}
	namespaceSelector := reconciler.webhookNamespaceSelector(policy)
	if namespaceSelector != nil {
		t.Error("No namespace selector should be defined")
	}

	reconciler = Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: true,
	}
	policy = &kubewardenv1.ClusterAdmissionPolicy{
		Spec: kubewardenv1.ClusterAdmissionPolicySpec{},
	}
	namespaceSelector = reconciler.webhookNamespaceSelector(policy)
	if namespaceSelector.MatchExpressions == nil || len(namespaceSelector.MatchExpressions) != 1 {
		t.Errorf("Namespace selector should have only the previous selectors and another one to skip Kuberwarden namespace. Selectors found: %d", len(namespaceSelector.MatchExpressions))
		return
	}
	if namespaceSelector.MatchExpressions[0].Key != constants.KubernetesNamespaceNameLabel {
		t.Error("Selector to skip Kuberwarden namespace has invalid key")
	}
	if namespaceSelector.MatchExpressions[0].Operator != metav1.LabelSelectorOpNotIn {
		t.Error("Selector to skip Kuberwarden namespace has invalid operator")
	}
	if len(namespaceSelector.MatchExpressions[0].Values) != 1 || namespaceSelector.MatchExpressions[0].Values[0] != "kubewarden" {
		t.Error("Selector to skip Kuberwarden namespace has invalid namespace")
	}
}
