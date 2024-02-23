package scheme

import (
	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

func NewScheme() *runtime.Scheme {
	scheme := scheme.Scheme

	scheme.AddKnownTypes(
		schema.GroupVersion{Group: constants.KubewardenPoliciesGroup, Version: constants.KubewardenPoliciesVersion},
		&policiesv1.ClusterAdmissionPolicy{},
		&policiesv1.AdmissionPolicy{},
		&policiesv1.ClusterAdmissionPolicyList{},
		&policiesv1.AdmissionPolicyList{},
		&policiesv1.PolicyServer{},
	)
	metav1.AddToGroupVersion(
		scheme, schema.GroupVersion{Group: constants.KubewardenPoliciesGroup, Version: constants.KubewardenPoliciesVersion},
	)

	return scheme
}
