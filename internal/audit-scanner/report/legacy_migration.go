package report

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// DeleteAllLegacyPolicyReports deletes all wgpolicyk8s.io PolicyReports and
// ClusterPolicyReports labelled app.kubernetes.io/managed-by=kubewarden.
//
// This is called once per scan when scans save openreports.
//
// The deletion is performed with existing functions that do performant
// deletecollection api calls.
//
// For reducing cost in subsequent runs, it checks for the existence of legacy
// wgpolicyk8s.io reports before attempting deletion: in clusters with many
// namespaces the cost after the first migration is just two cheap List calls.
func DeleteAllLegacyPolicyReports(ctx context.Context, c client.Client, logger *slog.Logger) error {
	// The store.DeleteOldReports() functions that we are reusing delete stale
	// reports prior to saving a new scan. They do this by using a scanRunID.
	// Here, a fresh UUID is used as the scanRunID: since no existing report will carry
	// this UID, the "run-uid != <id>" selector matches all of them, effectively
	// deleting every kubewarden-managed report.
	ephemeralRunUID := uuid.New().String()
	store := NewPolicyReportStore(c, logger)

	labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s", labelAppManagedBy, labelApp))
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}
	// After first migration, we will perform 2 list calls, one for
	// ClusterPolicyReport, another for PolicyReport, both with limit=1.
	listOpts := &client.ListOptions{LabelSelector: labelSelector, Limit: 1}

	clusterReportList := &wgpolicy.ClusterPolicyReportList{}
	err = c.List(ctx, clusterReportList, listOpts)
	switch {
	case meta.IsNoMatchError(err):
		logger.DebugContext(ctx, "wgpolicyk8s.io CRDs not installed, skipping legacy clusterreport cleanup")
	case err != nil:
		return fmt.Errorf("failed to list legacy ClusterPolicyReports: %w", err)
	case len(clusterReportList.Items) > 0:
		logger.InfoContext(ctx, "Deleting legacy wgpolicyk8s.io ClusterPolicyReports")
		if err = store.DeleteOldClusterReports(ctx, ephemeralRunUID); err != nil {
			return err
		}
	}

	policyReportList := &wgpolicy.PolicyReportList{}
	err = c.List(ctx, policyReportList, listOpts)
	switch {
	case meta.IsNoMatchError(err):
		logger.DebugContext(ctx, "wgpolicyk8s.io CRDs not installed, skipping legacy report cleanup")
	case err != nil:
		return fmt.Errorf("failed to list legacy PolicyReports: %w", err)
	case len(policyReportList.Items) > 0:
		namespaceList := &corev1.NamespaceList{}
		if err = c.List(ctx, namespaceList); err != nil {
			return fmt.Errorf("failed to list namespaces: %w", err)
		}
		for _, ns := range namespaceList.Items {
			logger.InfoContext(ctx, "Deleting legacy wgpolicyk8s.io PolicyReports",
				slog.String("namespace", ns.Name))
			if err = store.DeleteOldReports(ctx, ephemeralRunUID, ns.Name); err != nil {
				return err
			}
		}
	}

	return nil
}
