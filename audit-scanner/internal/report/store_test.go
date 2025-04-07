package report

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	auditConstants "github.com/kubewarden/audit-scanner/internal/constants"
	testutils "github.com/kubewarden/audit-scanner/internal/testutils"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestCreatePolicyReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewPolicyReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-pod")
	resource.SetNamespace("namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetResourceVersion("12345")

	policyReport := NewPolicyReport("runUID", resource)
	err = store.CreateOrPatchPolicyReport(context.TODO(), policyReport)
	require.NoError(t, err)

	storedPolicyReport := &wgpolicy.PolicyReport{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: policyReport.GetName(), Namespace: policyReport.GetNamespace()}, storedPolicyReport)
	require.NoError(t, err)

	require.Equal(t, policyReport.ObjectMeta.Labels, storedPolicyReport.ObjectMeta.Labels)
	require.Equal(t, policyReport.ObjectMeta.OwnerReferences, storedPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, policyReport.Scope, storedPolicyReport.Scope)
	require.Equal(t, policyReport.Summary, storedPolicyReport.Summary)
	require.Equal(t, policyReport.Results, storedPolicyReport.Results)
}

func TestPatchPolicyReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewPolicyReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-pod")
	resource.SetNamespace("test-namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetResourceVersion("12345")

	policyReport := NewPolicyReport("runUID", resource)
	err = store.CreateOrPatchPolicyReport(context.TODO(), policyReport)
	require.NoError(t, err)

	// The resource version is updated to simulate a change in the resource.
	resource.SetResourceVersion("45678")
	newPolicyReport := NewPolicyReport("runUID", resource)
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
	AddResultToPolicyReport(newPolicyReport, policy, admissionReview, false)
	err = store.CreateOrPatchPolicyReport(context.TODO(), newPolicyReport)
	require.NoError(t, err)

	storedPolicyReport := &wgpolicy.PolicyReport{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: policyReport.GetName(), Namespace: policyReport.GetNamespace()}, storedPolicyReport)
	require.NoError(t, err)

	require.Equal(t, newPolicyReport.ObjectMeta.Labels, storedPolicyReport.ObjectMeta.Labels)
	require.Equal(t, newPolicyReport.ObjectMeta.OwnerReferences, storedPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, newPolicyReport.Scope, storedPolicyReport.Scope)
	require.Equal(t, newPolicyReport.Summary, storedPolicyReport.Summary)
	require.Equal(t, newPolicyReport.Results, storedPolicyReport.Results)
}

func TestCreateClusterPolicyReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewPolicyReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Namespace")
	resource.SetResourceVersion("12345")

	clusterPolicyReport := NewClusterPolicyReport("runUID", resource)
	err = store.CreateOrPatchClusterPolicyReport(context.TODO(), clusterPolicyReport)
	require.NoError(t, err)

	storedClusterPolicyReport := &wgpolicy.ClusterPolicyReport{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: clusterPolicyReport.GetName()}, storedClusterPolicyReport)
	require.NoError(t, err)

	require.Equal(t, clusterPolicyReport.ObjectMeta.Labels, storedClusterPolicyReport.ObjectMeta.Labels)
	require.Equal(t, clusterPolicyReport.ObjectMeta.OwnerReferences, storedClusterPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, clusterPolicyReport.Scope, storedClusterPolicyReport.Scope)
	require.Equal(t, clusterPolicyReport.Summary, storedClusterPolicyReport.Summary)
	require.Equal(t, clusterPolicyReport.Results, storedClusterPolicyReport.Results)
}

func TestPatchClusterPolicyReport(t *testing.T) {
	fakeClient, err := testutils.NewFakeClient()
	require.NoError(t, err)
	logger := slog.Default()
	store := NewPolicyReportStore(fakeClient, logger)

	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetAPIVersion("v1")
	resource.SetKind("Namespace")
	resource.SetName("test-namespace")
	resource.SetResourceVersion("12345")

	clusterPolicyReport := NewClusterPolicyReport("runUID", resource)
	err = store.CreateOrPatchClusterPolicyReport(context.TODO(), clusterPolicyReport)
	require.NoError(t, err)

	// The resource version is updated to simulate a change in the resource.
	resource.SetResourceVersion("45678")
	newClusterPolicyReport := NewClusterPolicyReport("runUID", resource)
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
	AddResultToClusterPolicyReport(newClusterPolicyReport, policy, admissionReview, false)
	err = store.CreateOrPatchClusterPolicyReport(context.TODO(), newClusterPolicyReport)
	require.NoError(t, err)

	storedClusterPolicyReport := &wgpolicy.ClusterPolicyReport{}
	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: clusterPolicyReport.GetName()}, storedClusterPolicyReport)
	require.NoError(t, err)

	require.Equal(t, newClusterPolicyReport.ObjectMeta.Labels, storedClusterPolicyReport.ObjectMeta.Labels)
	require.Equal(t, newClusterPolicyReport.ObjectMeta.OwnerReferences, storedClusterPolicyReport.ObjectMeta.OwnerReferences)
	require.Equal(t, newClusterPolicyReport.Scope, storedClusterPolicyReport.Scope)
	require.Equal(t, newClusterPolicyReport.Summary, storedClusterPolicyReport.Summary)
	require.Equal(t, newClusterPolicyReport.Results, storedClusterPolicyReport.Results)
}

func TestDeletePolicyReport(t *testing.T) {
	oldPolicyReport := testutils.NewPolicyReportFactory().
		Name("old-report").Namespace("default").RunUID("old-uid").WithAppLabel().Build()
	otherOldPolicyReport := testutils.NewPolicyReportFactory().
		Name("other-old-report").Namespace("default").RunUID("old-uid").Build()
	newPolicyReport := testutils.NewPolicyReportFactory().
		Name("new-report").Namespace("default").RunUID("new-uid").WithAppLabel().Build()
	oldPolicyReportOtheNamespace := testutils.NewPolicyReportFactory().
		Name("old-report-other-namespace").Namespace("other").RunUID("old-uid").WithAppLabel().Build()

	fakeClient, err := testutils.NewFakeClient(oldPolicyReport, otherOldPolicyReport, newPolicyReport, oldPolicyReportOtheNamespace)
	require.NoError(t, err)
	logger := slog.Default()
	store := NewPolicyReportStore(fakeClient, logger)

	err = store.DeleteOldPolicyReports(context.Background(), "new-uid", "default")
	require.NoError(t, err)

	storedPolicyReportList := &wgpolicy.PolicyReportList{}

	err = fakeClient.List(context.TODO(), storedPolicyReportList, &client.ListOptions{Namespace: "other"})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)

	labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(context.TODO(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector, Namespace: "default"})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
	require.Equal(t, "other-old-report", storedPolicyReportList.Items[0].Name)

	labelSelector, err = labels.Parse(fmt.Sprintf("%s!=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(context.TODO(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector, Namespace: "default"})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
}

func TestDeleteClusterPolicyReport(t *testing.T) {
	oldPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("old-report-with-app-label").WithAppLabel().RunUID("old-uid").Build()
	otherOldPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("old-report-with-no-app-label").RunUID("old-uid").Build()
	newPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("new-report").WithAppLabel().RunUID("new-uid").Build()
	fakeClient, err := testutils.NewFakeClient(oldPolicyReport, otherOldPolicyReport, newPolicyReport)
	require.NoError(t, err)
	logger := slog.Default()
	store := NewPolicyReportStore(fakeClient, logger)

	err = store.DeleteOldClusterPolicyReports(context.Background(), "new-uid")
	require.NoError(t, err)

	storedPolicyReportList := &wgpolicy.ClusterPolicyReportList{}

	labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(context.TODO(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
	require.Equal(t, "old-report-with-no-app-label", storedPolicyReportList.Items[0].Name)

	storedPolicyReportList = &wgpolicy.ClusterPolicyReportList{}

	labelSelector, err = labels.Parse(fmt.Sprintf("%s!=%s", auditConstants.AuditScannerRunUIDLabel, "old-uid"))
	require.NoError(t, err)
	err = fakeClient.List(context.TODO(), storedPolicyReportList, &client.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)
	require.Len(t, storedPolicyReportList.Items, 1)
}
