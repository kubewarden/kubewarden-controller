package report_test

import (
	"testing"

	"github.com/kubewarden/audit-scanner/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

var cpr = report.ClusterPolicyReport{
	v1alpha2.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "polr-clusterwide",
			CreationTimestamp: metav1.Now(),
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []*v1alpha2.PolicyReportResult{},
	},
}

var npr = report.PolicyReport{
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
	store, _ := report.NewPolicyReportStore()

	t.Run("Add then Get namespaced PolicyReport", func(t *testing.T) {
		_, err := store.GetPolicyReport(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should not be found in empty Store")
		}

		_ = store.AddPolicyReport(&npr)
		_, err = store.GetPolicyReport(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
	})

	t.Run("Update then Get namespaced PolicyReport", func(t *testing.T) {
		upr := report.PolicyReport{
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

		_ = store.AddPolicyReport(&npr)
		r, err := store.GetPolicyReport(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
		if r.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 0")
		}

		_ = store.UpdatePolicyReport(&upr)
		r2, _ := store.GetPolicyReport(npr.GetNamespace())
		if r2.Summary.Skip != 1 {
			t.Errorf("Expected Summary.Skip to be 1 after update")
		}
	})

	t.Run("Delete then Get namespaced PolicyReport", func(t *testing.T) {
		_, err := store.GetPolicyReport(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}

		_ = store.RemovePolicyReport(npr.GetNamespace())
		_, err = store.GetPolicyReport(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should not be found after Remove report from Store")
		}
	})

	t.Run("Remove all namespaced", func(t *testing.T) {
		_ = store.AddPolicyReport(&npr)

		_ = store.RemoveAllNamespacedPolicyReports()
		_, err := store.GetPolicyReport(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should have no results after CleanUp")
		}
	})

	t.Run("Clusterwide Add then Get", func(t *testing.T) {
		_ = store.AddClusterPolicyReport(&cpr)
		_, err := store.GetClusterPolicyReport()
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
	})

	t.Run("Clusterwide Update then Get", func(t *testing.T) {
		cprWithSkip := report.ClusterPolicyReport{
			v1alpha2.ClusterPolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-clusterwide-test",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{Skip: 1},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		_ = store.AddClusterPolicyReport(&cpr)
		r, err := store.GetClusterPolicyReport()
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
		if r.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 0")
		}

		_ = store.UpdateClusterPolicyReport(&cprWithSkip)
		r2, _ := store.GetClusterPolicyReport()
		if r2.Summary.Skip != 1 {
			t.Errorf("Expected Summary.Skip to be 1 after update")
		}
	})
}
