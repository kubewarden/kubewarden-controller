package admission

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
)

func (r *Reconciler) webhookNamespaceSelector(policy v1alpha2.Policy) *metav1.LabelSelector {
	namespaceSelector := policy.GetNamespaceSelector()
	if r.AlwaysAcceptAdmissionReviewsInDeploymentsNamespace {
		if namespaceSelector == nil {
			namespaceSelector = &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{},
			}
		}
		skipKubewardenNamespaceSelector := metav1.LabelSelectorRequirement{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{r.DeploymentsNamespace},
		}
		namespaceSelector.MatchExpressions = append(namespaceSelector.MatchExpressions, skipKubewardenNamespaceSelector)
	}
	return namespaceSelector
}
