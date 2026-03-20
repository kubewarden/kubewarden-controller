package report

import (
	"log/slog"
	"testing"

	testutils "github.com/kubewarden/kubewarden-controller/internal/audit-scanner/testutils"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestDeleteAllLegacyPolicyReports(t *testing.T) {
	nsDefault := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	nsOther := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other"}}

	// kubewarden-managed reports in two namespaces should be deleted
	managedDefault := testutils.NewPolicyReportFactory().
		Name("managed-default").Namespace("default").RunUID("old-uid").WithAppLabel().Build()
	managedOther := testutils.NewPolicyReportFactory().
		Name("managed-other").Namespace("other").RunUID("old-uid").WithAppLabel().Build()
	// report without the managed-by label should be preserved
	unmanagedDefault := testutils.NewPolicyReportFactory().
		Name("unmanaged-default").Namespace("default").RunUID("old-uid").Build()

	// kubewarden-managed cluster report should be deleted
	managedCluster := testutils.NewClusterPolicyReportFactory().
		Name("managed-cluster").WithAppLabel().RunUID("old-uid").Build()
	// cluster report without the managed-by label should be preserved
	unmanagedCluster := testutils.NewClusterPolicyReportFactory().
		Name("unmanaged-cluster").RunUID("old-uid").Build()

	fakeClient, err := testutils.NewFakeClient(
		nsDefault, nsOther,
		managedDefault, managedOther, unmanagedDefault,
		managedCluster, unmanagedCluster,
	)
	require.NoError(t, err)

	err = DeleteAllLegacyPolicyReports(t.Context(), fakeClient, slog.Default())
	require.NoError(t, err)

	// all namespaced kubewarden-managed reports are gone
	policyReportList := &wgpolicy.PolicyReportList{}
	err = fakeClient.List(t.Context(), policyReportList)
	require.NoError(t, err)
	require.Len(t, policyReportList.Items, 1)
	require.Equal(t, "unmanaged-default", policyReportList.Items[0].Name)

	// all cluster kubewarden-managed reports are gone
	clusterReportList := &wgpolicy.ClusterPolicyReportList{}
	err = fakeClient.List(t.Context(), clusterReportList, &client.ListOptions{})
	require.NoError(t, err)
	require.Len(t, clusterReportList.Items, 1)
	require.Equal(t, "unmanaged-cluster", clusterReportList.Items[0].Name)
}
