package report_test

import (
	"testing"

	"github.com/kubewarden/audit-scanner/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestAddMemoryPolicyReportStore(t *testing.T) {
	t.Run("Add then Get namespaced PolicyReport", func(t *testing.T) {
		store := report.NewMemoryPolicyReportStore()

		_, err := store.GetPolicyReport(npr.GetNamespace())
		if err == nil {
			t.Errorf("Should not find PolicyReport in empty Store")
		}

		err = store.SavePolicyReport(&npr)
		if err != nil {
			t.Errorf("Cannot save report: %v", err)
		}

		_, err = store.GetPolicyReport(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store: %v.", err)
		}
	})

	t.Run("Clusterwide Add then Get", func(t *testing.T) {
		store := report.NewMemoryPolicyReportStore()

		err := store.SaveClusterPolicyReport(&cpr)
		if err != nil {
			t.Errorf("Cannot save report: %v", err)
		}

		_, err = store.GetClusterPolicyReport(cpr.ObjectMeta.Name)
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
	})
}

func TestSaveMemoryReports(t *testing.T) {
	t.Run("Save ClusterPolicyReport (create)", func(t *testing.T) {
		store := report.NewMemoryPolicyReportStore()

		report := report.NewClusterPolicyReport("testing")
		err := store.SaveClusterPolicyReport(&report)
		// always updates ClusterPolicyReport,
		// store initializes with blank ClusterPolicyReport
		if err != nil {
			t.Errorf("Should not return errors: %v", err)
		}
	})

	t.Run("Save PolicyReport (create)", func(t *testing.T) {
		store := report.NewMemoryPolicyReportStore()

		npr2 := report.PolicyReport{
			PolicyReport: v1alpha2.PolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-ns-test2",
					Namespace:         "test2",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		err := store.SavePolicyReport(&npr2)
		if err != nil {
			t.Errorf("Should not return errors: %v", err)
		}

		_, err = store.GetPolicyReport(npr2.GetNamespace())
		if err != nil {
			t.Errorf("Should not return errors: %v", err)
		}
	})

	t.Run("Save PolicyReport (update)", func(t *testing.T) {
		store := report.NewMemoryPolicyReportStore()

		// copy first resource version
		upr := npr
		// do some change
		upr.Summary = v1alpha2.PolicyReportSummary{Skip: 1}

		err := store.SavePolicyReport(&upr)
		if err != nil {
			t.Errorf("Should not return errors: %v", err)
		}

		getObj, err := store.GetPolicyReport(npr.GetNamespace())
		if err != nil {
			t.Errorf("Should not return errors: %v", err)
		}
		if getObj.Summary.Skip != 1 {
			t.Errorf("Expected Summary.Skip to be 1 after update. Object returned: %v", getObj)
		}
	})
}
