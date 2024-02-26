//go:build testing

package testutils

import (
	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/kubewarden/audit-scanner/internal/scheme"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func NewFakeClient(objects ...runtime.Object) client.Client {
	groupVersion := []schema.GroupVersion{
		{Group: "", Version: "v1"},
		{Group: "apps", Version: "v1"},
	}
	restMapper := meta.NewDefaultRESTMapper(groupVersion)
	restMapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}, meta.RESTScopeNamespace)
	restMapper.Add(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, meta.RESTScopeNamespace)
	restMapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)

	return fake.NewClientBuilder().WithRESTMapper(restMapper).WithScheme(scheme.NewScheme()).WithRuntimeObjects(objects...).Build()
}

type AdmissionPolicyFactory struct {
	name            string
	namespace       string
	objectSelector  *metav1.LabelSelector
	rules           []admissionregistrationv1.RuleWithOperations
	backgroundAudit bool
	status          policiesv1.PolicyStatusEnum
}

func NewAdmissionPolicyFactory() *AdmissionPolicyFactory {
	return &AdmissionPolicyFactory{
		backgroundAudit: true,
		status:          policiesv1.PolicyStatusActive,
	}
}

func (factory *AdmissionPolicyFactory) Name(name string) *AdmissionPolicyFactory {
	factory.name = name

	return factory
}

func (factory *AdmissionPolicyFactory) Namespace(namespace string) *AdmissionPolicyFactory {
	factory.namespace = namespace

	return factory
}

func (factory *AdmissionPolicyFactory) ObjectSelector(selector *metav1.LabelSelector) *AdmissionPolicyFactory {
	factory.objectSelector = selector

	return factory
}

func (factory *AdmissionPolicyFactory) Rule(rule admissionregistrationv1.Rule) *AdmissionPolicyFactory {
	factory.rules = append(factory.rules, admissionregistrationv1.RuleWithOperations{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create}, Rule: rule,
	})

	return factory
}

func (factory *AdmissionPolicyFactory) BackgroundAudit(backgroundAudit bool) *AdmissionPolicyFactory {
	factory.backgroundAudit = backgroundAudit

	return factory
}

func (factory *AdmissionPolicyFactory) Status(status policiesv1.PolicyStatusEnum) *AdmissionPolicyFactory {
	factory.status = status

	return factory
}

func (factory *AdmissionPolicyFactory) Build() *policiesv1.AdmissionPolicy {
	policy := &policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      factory.name,
			Namespace: factory.namespace,
		},
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				ObjectSelector:  factory.objectSelector,
				PolicyServer:    "default",
				Rules:           factory.rules,
				BackgroundAudit: factory.backgroundAudit,
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: factory.status,
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicy,
	})

	return policy
}

type ClusterAdmissionPolicyFactory struct {
	name              string
	namespaceSelector *metav1.LabelSelector
	objectSelector    *metav1.LabelSelector
	rules             []admissionregistrationv1.RuleWithOperations
	backgroundAudit   bool
	status            policiesv1.PolicyStatusEnum
}

func NewClusterAdmissionPolicyFactory() *ClusterAdmissionPolicyFactory {
	return &ClusterAdmissionPolicyFactory{
		backgroundAudit: true,
		status:          policiesv1.PolicyStatusActive,
	}
}

func (factory *ClusterAdmissionPolicyFactory) Name(name string) *ClusterAdmissionPolicyFactory {
	factory.name = name

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) NamespaceSelector(selector *metav1.LabelSelector) *ClusterAdmissionPolicyFactory {
	factory.namespaceSelector = selector

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) ObjectSelector(selector *metav1.LabelSelector) *ClusterAdmissionPolicyFactory {
	factory.objectSelector = selector

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) Rule(rule admissionregistrationv1.Rule) *ClusterAdmissionPolicyFactory {
	factory.rules = append(factory.rules, admissionregistrationv1.RuleWithOperations{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create}, Rule: rule,
	})

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) BackgroundAudit(backgroundAudit bool) *ClusterAdmissionPolicyFactory {
	factory.backgroundAudit = backgroundAudit

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) Status(status policiesv1.PolicyStatusEnum) *ClusterAdmissionPolicyFactory {
	factory.status = status

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) Build() *policiesv1.ClusterAdmissionPolicy {
	policy := &policiesv1.ClusterAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       constants.KubewardenKindClusterAdmissionPolicy,
			APIVersion: constants.KubewardenPoliciesVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: factory.name,
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			NamespaceSelector: factory.namespaceSelector,
			PolicySpec: policiesv1.PolicySpec{
				ObjectSelector:  factory.objectSelector,
				PolicyServer:    "default",
				Rules:           factory.rules,
				BackgroundAudit: factory.backgroundAudit,
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: factory.status,
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	})

	return policy
}
