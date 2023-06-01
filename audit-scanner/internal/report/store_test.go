package report_test

import (
	"testing"

	"github.com/kubewarden/audit-scanner/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

var cpr = &report.ClusterPolicyReport{
	v1alpha2.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "polr-clusterwide",
			CreationTimestamp: metav1.Now(),
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []*v1alpha2.PolicyReportResult{},
	},
}

var npr = &report.PolicyReport{
	v1alpha2.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "polr-ns-test",
			Namespace:         "test",
			CreationTimestamp: metav1.Now(),
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []*v1alpha2.PolicyReportResult{},
	},
}

func Test_PolicyReportStore(t *testing.T) {
	store := report.NewPolicyReportStore()

	t.Run("Add then Get", func(t *testing.T) {
		_, err := store.Get(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should not be found in empty Store")
		}

		_ = store.Add(npr)
		_, err = store.Get(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
	})

	t.Run("Update then Get", func(t *testing.T) {
		upr := &report.PolicyReport{
			v1alpha2.PolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-ns-test",
					Namespace:         "test",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{Skip: 1},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		_ = store.Add(npr)
		r, _ := store.Get(npr.GetNamespace())
		if rep, _ := r.(*report.PolicyReport); rep.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 0")
		}

		_ = store.Update(upr)
		r2, _ := store.Get(npr.GetNamespace())
		if rep2, _ := r2.(*report.PolicyReport); rep2.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 1 after update")
		}
	})

	t.Run("Delete then Get", func(t *testing.T) {
		_, err := store.Get(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}

		_ = store.Remove(npr.GetNamespace())
		_, err = store.Get(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should not be found after Remove report from Store")
		}
	})

	t.Run("Remove all namespaced", func(t *testing.T) {
		_ = store.Add(npr)

		_ = store.RemoveAllNamespaced()
		_, err := store.Get(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should have no results after CleanUp")
		}
	})

	t.Run("Clusterwide Add then Get", func(t *testing.T) {
		_ = store.Add(cpr)
		_, err := store.GetClusterWide()
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
	})

	t.Run("Clusterwide Update then Get", func(t *testing.T) {
		cprWithSkip := &report.ClusterPolicyReport{
			v1alpha2.ClusterPolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-clusterwide-test",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{Skip: 1},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		_ = store.Add(cprWithSkip)
		r, _ := store.GetClusterWide()
		if rep, _ := r.(*report.ClusterPolicyReport); rep.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 0")
		}

		_ = store.Update(cpr)
		r2, _ := store.Get(npr.GetNamespace())
		if rep2, _ := r2.(*report.ClusterPolicyReport); rep2.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 1 after update")
		}
	})
}
