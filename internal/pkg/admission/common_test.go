package admission

import (
	"time"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createReconciler() (Reconciler, policiesv1alpha2.ClusterAdmissionPolicy, policiesv1alpha2.ClusterAdmissionPolicy) {
	admissionPolicyName := "admissionPolicy"
	validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: admissionPolicyName,
		},
	}
	validationPolicy := policiesv1alpha2.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &metav1.Time{Time: time.Now()}, Name: admissionPolicyName, Finalizers: []string{"kubewarden"}},
		Spec:       policiesv1alpha2.ClusterAdmissionPolicySpec{Mutating: false, Module: "registry://blabla/validation-policy:latest"},
	}
	mutatingPolicyName := "mutatingPolicy"
	mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: mutatingPolicyName,
		},
	}
	mutatingPolicy := policiesv1alpha2.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &metav1.Time{Time: time.Now()}, Name: mutatingPolicyName, Finalizers: []string{"kubewarden"}},
		Spec:       policiesv1alpha2.ClusterAdmissionPolicySpec{Mutating: true, Module: "registry://blabla/mutation-policy:latest"},
	}
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: "policies.kubewarden.io", Version: "v1alpha2"}, &validationPolicy)
	cl := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(validatingWebhook, mutatingWebhook, &validationPolicy, &mutatingPolicy).Build()
	reconciler := Reconciler{
		Client:               cl,
		DeploymentsNamespace: namespace,
	}
	return reconciler, validationPolicy, mutatingPolicy
}
