package admission

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDeletePendingClusterAdmissionPolicies(t *testing.T) {
	reconciler, validationPolicy, mutatingPolicy := createReconciler()
	clusterAdmissionPolicies := []policiesv1alpha2.Policy{&validationPolicy, &mutatingPolicy}

	err := reconciler.deleteWebhooksClusterAdmissionPolicies(context.Background(), clusterAdmissionPolicies)
	if err != nil {
		t.Errorf("received unexpected error %s", err.Error())
	}

	// verify webhooks are deleted
	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: validationPolicy.Name,
	}, validatingWebhook)
	if !errors.IsNotFound(err) {
		t.Errorf("validating webhook not deleted")
	}
	mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: mutatingPolicy.Name,
	}, mutatingWebhook)
	if !errors.IsNotFound(err) {
		t.Errorf("mutating webhook not deleted")
	}

	// verify cluster admission policies finalizers are deleted
	policy := &policiesv1alpha2.ClusterAdmissionPolicy{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: validationPolicy.Name,
	}, policy)
	if err != nil && errors.IsNotFound(err) {
		// return early from the test, as because of the lack of finalizers, the resource has been
		// garbage collected. We cannot test for the lack of our finalizers, but we know that the
		// resource disappeared due to the lack of our finalizer, so it is also a success case.
		return
	} else if err != nil {
		t.Errorf("received unexpected error %s", err.Error())
	}
	if len(policy.Finalizers) != 0 {
		t.Errorf("validating policy finalizers should be empty, but found %s", policy.Finalizers)
	}
	policy = &policiesv1alpha2.ClusterAdmissionPolicy{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: mutatingPolicy.Name,
	}, policy)
	if err != nil {
		t.Errorf("received unexpected error %s", err.Error())
	}
	if len(policy.Finalizers) != 0 {
		t.Errorf("mutating policy finalizers should be empty, but found %s", policy.Finalizers)
	}
}

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
			[]client.Object{&policiesv1alpha2.ClusterAdmissionPolicy{Spec: policiesv1alpha2.ClusterAdmissionPolicySpec{PolicyServer: policyServer}}},
			1,
		},
		{
			"with namespaced and no cluster policies",
			[]client.Object{&policiesv1alpha2.AdmissionPolicy{Spec: policiesv1alpha2.AdmissionPolicySpec{PolicyServer: policyServer}}},
			1,
		},
		{
			"with cluster and namespaced policies",
			[]client.Object{&policiesv1alpha2.ClusterAdmissionPolicy{Spec: policiesv1alpha2.ClusterAdmissionPolicySpec{PolicyServer: policyServer}}, &policiesv1alpha2.AdmissionPolicy{Spec: policiesv1alpha2.AdmissionPolicySpec{PolicyServer: policyServer}}},
			2,
		},
	}
	for _, test := range tests {
		ttest := test // ensure ttest is correctly scoped when used in function literal
		t.Run(ttest.name, func(t *testing.T) {
			reconciler := newReconciler(test.policies)
			policies, err := reconciler.getPolicies(context.Background(), &policiesv1alpha2.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{Name: policyServer},
			})
			if err != nil {
				t.Errorf("received unexpected error %s", err.Error())
			}
			if len(policies) != test.expect {
				t.Errorf("expected %d, but got %d", test.expect, len(policies))
			}
		})
	}
}

func newReconciler(policies []client.Object) Reconciler {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: "policies.kubewarden.io", Version: "v1alpha2"}, &policiesv1alpha2.ClusterAdmissionPolicy{}, &policiesv1alpha2.AdmissionPolicy{}, &policiesv1alpha2.ClusterAdmissionPolicyList{}, &policiesv1alpha2.AdmissionPolicyList{})
	cl := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(policies...).Build()

	return Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
}
