package v1

import (
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetNamespaceSelectorWithEmptyNamespaceSelector(t *testing.T) {
	kubewardenNs := "kubewarden"
	c := ClusterAdmissionPolicy{}
	nsSelector := c.GetNamespaceSelector(kubewardenNs)
	isKubewardenNsFound := isNamespaceFoundInSelector(nsSelector, kubewardenNs)

	if !isKubewardenNsFound {
		t.Errorf("Kubewarden namespace not added to namespace selector")
	}
}

func TestGetNamespaceSelectorWithExistingMatchExpressions(t *testing.T) {
	kubewardenNs := "kubewarden"
	policy := ClusterAdmissionPolicy{
		Spec: ClusterAdmissionPolicySpec{
			NamespaceSelector: &v1.LabelSelector{
				MatchExpressions: []v1.LabelSelectorRequirement{
					{
						Key:      "In",
						Operator: "kubernetes.io/metadata.name",
						Values:   []string{"foo"},
					},
				},
			},
		},
	}
	nsSelector := policy.GetNamespaceSelector(kubewardenNs)
	isKubewardenNsFound := isNamespaceFoundInSelector(nsSelector, kubewardenNs)

	if !isKubewardenNsFound {
		t.Errorf("Kubewarden namespace not added to namespace selector")
	}
}

func isNamespaceFoundInSelector(selector *v1.LabelSelector, namespace string) bool {
	isKubewardenNsFound := false

	for _, matchExpression := range selector.MatchExpressions {
		if len(matchExpression.Values) == 1 &&
			matchExpression.Values[0] == namespace &&
			matchExpression.Key == "kubernetes.io/metadata.name" &&
			matchExpression.Operator == "NotIn" {
			isKubewardenNsFound = true
		}
	}

	return isKubewardenNsFound
}
