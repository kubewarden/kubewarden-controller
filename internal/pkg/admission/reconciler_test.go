package admission

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha2 "github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
			[]client.Object{&v1alpha2.ClusterAdmissionPolicy{Spec: v1alpha2.ClusterAdmissionPolicySpec{PolicyServer: policyServer}}},
			1,
		},
		{
			"with namespaced and no cluster policies",
			[]client.Object{&v1alpha2.AdmissionPolicy{Spec: v1alpha2.AdmissionPolicySpec{PolicyServer: policyServer}}},
			1,
		},
		{
			"with cluster and namespaced policies",
			[]client.Object{&v1alpha2.ClusterAdmissionPolicy{Spec: v1alpha2.ClusterAdmissionPolicySpec{PolicyServer: policyServer}}, &v1alpha2.AdmissionPolicy{Spec: v1alpha2.AdmissionPolicySpec{PolicyServer: policyServer}}},
			2,
		},
	}
	for _, test := range tests {
		ttest := test // ensure ttest is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			reconciler := newReconciler(ttest.policies)
			policies, err := reconciler.GetPolicies(context.Background(), &v1alpha2.PolicyServer{
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
	customScheme.AddKnownTypes(schema.GroupVersion{Group: "policies.kubewarden.io", Version: "v1alpha2"}, &v1alpha2.ClusterAdmissionPolicy{}, &v1alpha2.AdmissionPolicy{}, &v1alpha2.ClusterAdmissionPolicyList{}, &v1alpha2.AdmissionPolicyList{})
	cl := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(policies...).Build()

	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}
