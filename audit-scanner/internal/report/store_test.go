package report_test

import (
	"context"
	"testing"

	"github.com/kubewarden/audit-scanner/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
	store := report.MockNewPolicyReportStore(nil)

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

func TestSaveReports(t *testing.T) {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		v1alpha2.SchemeGroupVersion,
		&v1alpha2.PolicyReport{},
		&v1alpha2.ClusterPolicyReport{},
		&v1alpha2.PolicyReportList{},
		&v1alpha2.ClusterPolicyReportList{},
	)
	//nolint
	// fake client has been undeprecated due to overwhemling feedback
	// https://github.com/kubernetes-sigs/controller-runtime/pull/1101
	cl := fake.NewFakeClientWithScheme(customScheme, &npr.PolicyReport, &cpr.ClusterPolicyReport)
	store := report.MockNewPolicyReportStore(cl)

	t.Run("Save ClusterPolicyReport (update)", func(t *testing.T) {
		if err := store.SaveClusterPolicyReport(); err != nil {
			// always updates ClusterPolicyReport, store initializes with blank
			// ClusterPolicReport
			t.Errorf("Should not return errors")
		}
	})

	t.Run("Save PolicyReport (update)", func(t *testing.T) {
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

		if err := store.SavePolicyReport(&upr); err != nil {
			t.Errorf("Should not return errors")
		}
		getObj := &v1alpha2.PolicyReport{}
		getErr := cl.Get(context.TODO(), types.NamespacedName{
			Namespace: npr.Namespace,
			Name:      npr.Name,
		}, getObj)
		if getErr != nil {
			t.Errorf("Should not return errors")
		}
		if getObj.Summary.Skip != 1 {
			t.Errorf("Expected Summary.Skip to be 1 after update")
		}
	})

	t.Run("Save PolicyReport (create)", func(t *testing.T) {
		npr2 := report.PolicyReport{
			v1alpha2.PolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-ns-test2",
					Namespace:         "test",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		if err := store.SavePolicyReport(&npr2); err != nil {
			t.Errorf("Should not return errors")
		}
		getObj := &v1alpha2.PolicyReport{}
		getErr := cl.Get(context.TODO(), types.NamespacedName{
			Namespace: npr2.Namespace,
			Name:      npr2.Name,
		}, getObj)
		if getErr != nil {
			t.Errorf("Should not return errors")
		}
	})
}
