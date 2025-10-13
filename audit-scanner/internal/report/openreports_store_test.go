package report

import (
	"fmt"
	"log/slog"
	"testing"

	auditConstants "github.com/kubewarden/audit-scanner/internal/constants"
	testutils "github.com/kubewarden/audit-scanner/internal/testutils"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestCreateReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewOpenReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-pod")
	resource.SetNamespace("namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetResourceVersion("12345")

	policyReport := NewOpenReport("runUID", resource)
	err = store.CreateOrPatchReport(t.Context(), policyReport)
	require.NoError(t, err)

	storedPolicyReport := &openreports.Report{}
	err = fakeClient.Get(t.Context(), types.NamespacedName{Name: policyReport.report.GetName(), Namespace: policyReport.report.GetNamespace()}, storedPolicyReport)
	require.NoError(t, err)

	require.Equal(t, policyReport.report.ObjectMeta.Labels, storedPolicyReport.ObjectMeta.Labels)
	require.Equal(t, policyReport.report.ObjectMeta.OwnerReferences, storedPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, policyReport.report.Scope, storedPolicyReport.Scope)
	require.Equal(t, policyReport.report.Summary, storedPolicyReport.Summary)
	require.Equal(t, policyReport.report.Results, storedPolicyReport.Results)
}

func TestPatchReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewOpenReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-pod")
	resource.SetNamespace("test-namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetResourceVersion("12345")

	policyReport := NewOpenReport("runUID", resource)
	err = store.CreateOrPatchReport(t.Context(), policyReport)
	require.NoError(t, err)

	// The resource version is updated to simulate a change in the resource.
	resource.SetResourceVersion("45678")
	newPolicyReport := NewOpenReport("runUID", resource)
	// Results are added to the policy report
	policy := &policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			UID:             "policy-uid",
			ResourceVersion: "1",
			Name:            "policy-name",
			Namespace:       "test-namespace",
		},
	}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: true,
			Result:  &metav1.Status{Message: "The request was allowed"},
		},
	}
	newPolicyReport.AddResult(policy, admissionReview, false)
	err = store.CreateOrPatchReport(t.Context(), newPolicyReport)
	require.NoError(t, err)

	storedPolicyReport := &openreports.Report{}
	err = fakeClient.Get(t.Context(), types.NamespacedName{Name: policyReport.report.GetName(), Namespace: policyReport.report.GetNamespace()}, storedPolicyReport)
	require.NoError(t, err)

	require.Equal(t, newPolicyReport.report.ObjectMeta.Labels, storedPolicyReport.ObjectMeta.Labels)
	require.Equal(t, newPolicyReport.report.ObjectMeta.OwnerReferences, storedPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, newPolicyReport.report.Scope, storedPolicyReport.Scope)
	require.Equal(t, newPolicyReport.report.Summary, storedPolicyReport.Summary)
	require.Equal(t, newPolicyReport.report.Results, storedPolicyReport.Results)
}

func TestCreateClusterReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewOpenReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Namespace")
	resource.SetResourceVersion("12345")

	clusterPolicyReport := NewClusterOpenReport("runUID", resource)
	err = store.CreateOrPatchClusterReport(t.Context(), clusterPolicyReport)
	require.NoError(t, err)

	storedClusterPolicyReport := &openreports.ClusterReport{}
	err = fakeClient.Get(t.Context(), types.NamespacedName{Name: clusterPolicyReport.report.GetName()}, storedClusterPolicyReport)
	require.NoError(t, err)

	require.Equal(t, clusterPolicyReport.report.ObjectMeta.Labels, storedClusterPolicyReport.ObjectMeta.Labels)
	require.Equal(t, clusterPolicyReport.report.ObjectMeta.OwnerReferences, storedClusterPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, clusterPolicyReport.report.Scope, storedClusterPolicyReport.Scope)
	require.Equal(t, clusterPolicyReport.report.Summary, storedClusterPolicyReport.Summary)
	require.Equal(t, clusterPolicyReport.report.Results, storedClusterPolicyReport.Results)
}

func TestPatchClusterReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewOpenReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetAPIVersion("v1")
	resource.SetKind("Namespace")
	resource.SetName("test-namespace")
	resource.SetResourceVersion("12345")

	clusterPolicyReport := NewClusterOpenReport("runUID", resource)
	err = store.CreateOrPatchClusterReport(t.Context(), clusterPolicyReport)
	require.NoError(t, err)

	// The resource version is updated to simulate a change in the resource.
	resource.SetResourceVersion("45678")
	newClusterPolicyReport := NewClusterOpenReport("runUID", resource)
	// Results are added to the policy report
	policy := &policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			UID:             "policy-uid",
			ResourceVersion: "1",
			Name:            "policy-name",
		},
	}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: true,
			Result:  &metav1.Status{Message: "The request was allowed"},
		},
	}
	newClusterPolicyReport.AddResult(policy, admissionReview, false)
	err = store.CreateOrPatchClusterReport(t.Context(), newClusterPolicyReport)
	require.NoError(t, err)

	storedClusterPolicyReport := &openreports.ClusterReport{}
	err = fakeClient.Get(t.Context(), types.NamespacedName{Name: clusterPolicyReport.report.GetName()}, storedClusterPolicyReport)
	require.NoError(t, err)

	require.Equal(t, newClusterPolicyReport.report.ObjectMeta.Labels, storedClusterPolicyReport.ObjectMeta.Labels)
	require.Equal(t, newClusterPolicyReport.report.ObjectMeta.OwnerReferences, storedClusterPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, newClusterPolicyReport.report.Scope, storedClusterPolicyReport.Scope)
	require.Equal(t, newClusterPolicyReport.report.Summary, storedClusterPolicyReport.Summary)
	require.Equal(t, newClusterPolicyReport.report.Results, storedClusterPolicyReport.Results)
}

func TestDeleteReport(t *testing.T) {
	oldPolicyReport := testutils.NewPolicyReportFactory().
		Name("old-report").Namespace("default").RunUID("old-uid").WithAppLabel().BuildOpenReports()
	otherOldPolicyReport := testutils.NewPolicyReportFactory().
		Name("other-old-report").Namespace("default").RunUID("old-uid").BuildOpenReports()
	newPolicyReport := testutils.NewPolicyReportFactory().
		Name("new-report").Namespace("default").RunUID("new-uid").WithAppLabel().BuildOpenReports()
	oldPolicyReportOtheNamespace := testutils.NewPolicyReportFactory().
		Name("old-report-other-namespace").Namespace("other").RunUID("old-uid").WithAppLabel().BuildOpenReports()

	fakeClient, err := testutils.NewFakeClient(oldPolicyReport, otherOldPolicyReport, newPolicyReport, oldPolicyReportOtheNamespace)
	require.NoError(t, err)
	logger := slog.Default()
	store := NewOpenReportStore(fakeClient, logger)

	err = store.DeleteOldReports(t.Context(), "new-uid", "default")
	require.NoError(t, err)

	storedPolicyReportList := &openreports.ReportList{}

	err = fakeClient.List(t.Context(), storedPolicyReportList, &client.ListOptions{Namespace: "other"})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)

	labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(t.Context(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector, Namespace: "default"})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
	require.Equal(t, "other-old-report", storedPolicyReportList.Items[0].Name)

	labelSelector, err = labels.Parse(fmt.Sprintf("%s!=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(t.Context(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector, Namespace: "default"})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
}

func TestDeleteClusterReport(t *testing.T) {
	oldPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("old-report-with-app-label").WithAppLabel().RunUID("old-uid").BuildOpenReports()
	otherOldPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("old-report-with-no-app-label").RunUID("old-uid").BuildOpenReports()
	newPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("new-report").WithAppLabel().RunUID("new-uid").BuildOpenReports()
	fakeClient, err := testutils.NewFakeClient(oldPolicyReport, otherOldPolicyReport, newPolicyReport)
	require.NoError(t, err)
	logger := slog.Default()
	store := NewOpenReportStore(fakeClient, logger)

	err = store.DeleteOldClusterReports(t.Context(), "new-uid")
	require.NoError(t, err)

	storedPolicyReportList := &openreports.ClusterReportList{}

	labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(t.Context(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
	require.Equal(t, "old-report-with-no-app-label", storedPolicyReportList.Items[0].Name)

	storedPolicyReportList = &openreports.ClusterReportList{}

	labelSelector, err = labels.Parse(fmt.Sprintf("%s!=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(t.Context(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
}
