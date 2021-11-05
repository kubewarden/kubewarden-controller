package admission

import (
	"context"
	"testing"
	"time"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDeletePendingClusterAdmissionPolicies(t *testing.T) {
	admissionPolicyName := "admissionPolicy"
	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: admissionPolicyName,
		},
	}
	validationPolicy := policiesv1alpha2.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &metav1.Time{Time: time.Now()}, Name: admissionPolicyName, Finalizers: []string{"kubewarden"}},
		Spec:       policiesv1alpha2.ClusterAdmissionPolicySpec{Mutating: false},
	}
	mutatingPolicyName := "mutatingPolicy"
	mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: mutatingPolicyName,
		},
	}
	mutatingPolicy := policiesv1alpha2.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &metav1.Time{Time: time.Now()}, Name: mutatingPolicyName, Finalizers: []string{"kubewarden"}},
		Spec:       policiesv1alpha2.ClusterAdmissionPolicySpec{Mutating: true},
	}
	clusterAdmissionPolicies := policiesv1alpha2.ClusterAdmissionPolicyList{Items: []policiesv1alpha2.ClusterAdmissionPolicy{validationPolicy, mutatingPolicy}}
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: "policies.kubewarden.io", Version: "v1alpha2"}, &validationPolicy)
	cl := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(validatingWebhook, mutatingWebhook, &validationPolicy, &mutatingPolicy).Build()
	reconciler := Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}

	err := reconciler.deletePendingClusterAdmissionPolicies(context.Background(), clusterAdmissionPolicies)
	if err != nil {
		t.Errorf("received unexpected error %s", err.Error())
	}

	// verify webhooks are deleted
	validatingWebhook = &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: admissionPolicyName,
	}, validatingWebhook)
	if !errors.IsNotFound(err) {
		t.Errorf("validating webhook not deleted")
	}
	mutatingWebhook = &admissionregistrationv1.MutatingWebhookConfiguration{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: mutatingPolicyName,
	}, mutatingWebhook)
	if !errors.IsNotFound(err) {
		t.Errorf("mutating webhook not deleted")
	}

	// verify cluster admission policies finalizers are deleted
	policy := &policiesv1alpha2.ClusterAdmissionPolicy{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Name: admissionPolicyName,
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
		Name: mutatingPolicyName,
	}, policy)
	if err != nil {
		t.Errorf("received unexpected error %s", err.Error())
	}
	if len(policy.Finalizers) != 0 {
		t.Errorf("mutating policy finalizers should be empty, but found %s", policy.Finalizers)
	}
}
