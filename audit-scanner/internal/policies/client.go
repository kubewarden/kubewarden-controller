package policies

import (
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newClient() (client.Client, error) {
	config := ctrl.GetConfigOrDie()
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion}, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion})

	return client.New(config, client.Options{Scheme: customScheme})
}
