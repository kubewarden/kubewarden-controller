package admission

import (
	"context"
	"testing"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDeletePendingClusterAdmissionPolicies(t *testing.T) {
	reconciler, validationPolicy, mutatingPolicy := createReconciler()
	clusterAdmissionPolicies := policiesv1alpha2.ClusterAdmissionPolicyList{Items: []policiesv1alpha2.ClusterAdmissionPolicy{validationPolicy, mutatingPolicy}}

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
