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

var labels = map[string]string{"app.kubernetes.io/managed-by": "kubewarden"}

var cpr = report.ClusterPolicyReport{
	v1alpha2.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "polr-clusterwide",
			CreationTimestamp: metav1.Now(),
			Labels:            labels,
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
			Labels:            labels,
		},
		Summary: v1alpha2.PolicyReportSummary{},
		Results: []*v1alpha2.PolicyReportResult{},
	},
}

func TestAddPolicyReportStore(t *testing.T) {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		v1alpha2.SchemeGroupVersion,
		&v1alpha2.PolicyReport{},
		&v1alpha2.ClusterPolicyReport{},
		&v1alpha2.PolicyReportList{},
		&v1alpha2.ClusterPolicyReportList{},
	)

	t.Run("Add then Get namespaced PolicyReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).Build()
		store := report.MockNewPolicyReportStore(client)
		_, err := store.GetPolicyReport(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should not be found in empty Store")
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
		client := fake.NewClientBuilder().WithScheme(customScheme).
			WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).
			Build()
		store := report.MockNewPolicyReportStore(client)
		_ = store.SaveClusterPolicyReport(&cpr)
		_, err := store.GetClusterPolicyReport(cpr.ObjectMeta.Name)
		if err != nil {
			t.Errorf("Should be found in Store after adding report to the store")
		}
	})
}

func TestUpdatePolicyReportStore(t *testing.T) {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		v1alpha2.SchemeGroupVersion,
		&v1alpha2.PolicyReport{},
		&v1alpha2.ClusterPolicyReport{},
		&v1alpha2.PolicyReportList{},
		&v1alpha2.ClusterPolicyReportList{},
	)

	//nolint:dupl
	t.Run("Update then Get namespaced PolicyReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).
			WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).Build()
		store := report.MockNewPolicyReportStore(client)

		err := store.SavePolicyReport(&npr)
		if err != nil {
			t.Fatalf("Cannot save PolicyReport: %v", err)
		}
		resource, err := store.GetPolicyReport(npr.GetNamespace())
		if err != nil {
			t.Fatalf("Should be found in Store after adding PolicyReport report to the store: %v", err)
		}
		if resource.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 0")
		}
		// copy first resource version
		upr := resource
		// do some change in the resource
		upr.Summary = v1alpha2.PolicyReportSummary{Skip: 1}

		err = store.UpdatePolicyReport(&upr)
		if err != nil {
			t.Fatalf("Cannot update PolicyReport: %v", err)
		}
		r2, _ := store.GetPolicyReport(npr.GetNamespace())
		if r2.Summary.Skip != 1 {
			t.Errorf("PolicyReport Expected Summary.Skip to be 1 after update")
		}
	})

	//nolint:dupl
	t.Run("Clusterwide Update then Get", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).
			WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).
			Build()
		store := report.MockNewPolicyReportStore(client)

		err := store.SaveClusterPolicyReport(&cpr)
		if err != nil {
			t.Fatalf("Cannot save ClusterPolicyReport: %v", err)
		}

		resource, err := store.GetClusterPolicyReport(cpr.GetName())
		if err != nil {
			t.Errorf("Should be found in Store after adding ClusterPolicyReport report to the store: %v", err)
		}
		if resource.Summary.Skip != 0 {
			t.Errorf("Expected Summary.Skip to be 0")
		}

		cprWithSkip := resource
		cprWithSkip.Summary = v1alpha2.PolicyReportSummary{Skip: 1}

		err = store.UpdateClusterPolicyReport(&cprWithSkip)
		if err != nil {
			t.Fatalf("Cannot update ClusterPolicyReport: %v", err)
		}
		r2, _ := store.GetClusterPolicyReport(cprWithSkip.GetName())
		if r2.Summary.Skip != 1 {
			t.Errorf("ClusterPolicyReport Expected Summary.Skip to be 1 after update")
		}
	})
}

func TestDeletePolicyReportStore(t *testing.T) {
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		v1alpha2.SchemeGroupVersion,
		&v1alpha2.PolicyReport{},
		&v1alpha2.ClusterPolicyReport{},
		&v1alpha2.PolicyReportList{},
		&v1alpha2.ClusterPolicyReportList{},
	)

	t.Run("Delete then Get namespaced PolicyReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).
			WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).Build()
		store := report.MockNewPolicyReportStore(client)
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
		client := fake.NewClientBuilder().WithScheme(customScheme).
			WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).Build()
		store := report.MockNewPolicyReportStore(client)
		_ = store.SavePolicyReport(&npr)

		_ = store.RemoveAllNamespacedPolicyReports()
		_, err := store.GetPolicyReport(npr.GetNamespace())
		if err == nil {
			t.Fatalf("Should have no results after CleanUp")
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

	t.Run("Save ClusterPolicyReport (create)", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).Build()
		store := report.MockNewPolicyReportStore(client)
		report := report.NewClusterPolicyReport("testing")
		if err := store.SaveClusterPolicyReport(&report); err != nil {
			// always updates ClusterPolicyReport, store initializes with blank
			// ClusterPolicReport
			t.Errorf("Should not return errors: %v", err)
		}
	})

	t.Run("Save PolicyReport (create)", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).Build()
		store := report.MockNewPolicyReportStore(client)
		npr2 := report.PolicyReport{
			v1alpha2.PolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-ns-test2",
					Namespace:         "test2",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		if err := store.SavePolicyReport(&npr2); err != nil {
			t.Errorf("Should not return errors: %v", err)
		}
		getObj := &v1alpha2.PolicyReport{}
		getErr := client.Get(context.TODO(), types.NamespacedName{
			Namespace: npr2.GetNamespace(),
			Name:      npr2.GetName(),
		}, getObj)
		if getErr != nil {
			t.Errorf("Should not return errors: %v", getErr)
		}
	})

	t.Run("Save PolicyReport (update)", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(customScheme).WithObjects(&npr.PolicyReport, &cpr.ClusterPolicyReport).Build()
		store := report.MockNewPolicyReportStore(client)
		// copy first resource version
		upr := npr
		// do some change
		upr.Summary = v1alpha2.PolicyReportSummary{Skip: 1}

		if err := store.SavePolicyReport(&upr); err != nil {
			t.Fatalf("Should not return errors: %v", err)
		}
		getObj := &v1alpha2.PolicyReport{}
		getErr := client.Get(context.TODO(), types.NamespacedName{
			Namespace: npr.GetNamespace(),
			Name:      npr.GetName(),
		}, getObj)
		if getErr != nil {
			t.Fatalf("Should not return errors: %v", getErr)
		}
		if getObj.Summary.Skip != 1 {
			t.Errorf("Expected Summary.Skip to be 1 after update. Object returned: %v", getObj)
		}
	})
}
