package report

import (
	"context"
	"fmt"
	"log/slog"

	auditConstants "github.com/kubewarden/kubewarden-controller/internal/audit-scanner/constants"
	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// OpenReportStore is a store for OpenReports Report and ClusterReport.
type OpenReportStore struct {
	// client is a controller-runtime client that knows about PolicyReport and ClusterPolicyReport CRDs
	client client.Client
	// logger is used to log the messages
	logger *slog.Logger
}

// NewOpenReportStore creates a new PolicyReportStore.
func NewOpenReportStore(client client.Client, logger *slog.Logger) Store {
	return &OpenReportStore{
		client: client,
		logger: logger.With("component", "policyreportstore"),
	}
}

// CreateOrPatchReport creates or patches a OpenReports Report.
func (s *OpenReportStore) CreateOrPatchReport(ctx context.Context, obj any) error {
	openReport, ok := obj.(*OpenReport)
	if !ok {
		return fmt.Errorf("expected *OpenReport, got %T", obj)
	}
	policyReport := openReport.report
	oldPolicyReport := &openreports.Report{ObjectMeta: metav1.ObjectMeta{
		Name:      policyReport.GetName(),
		Namespace: policyReport.GetNamespace(),
	}}

	operation, err := controllerutil.CreateOrPatch(ctx, s.client, oldPolicyReport, func() error {
		oldPolicyReport.ObjectMeta.Labels = policyReport.ObjectMeta.Labels
		oldPolicyReport.ObjectMeta.OwnerReferences = policyReport.ObjectMeta.OwnerReferences
		oldPolicyReport.Scope = policyReport.Scope
		oldPolicyReport.Summary = policyReport.Summary
		oldPolicyReport.Results = policyReport.Results

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or patch policy report %s: %w", policyReport.GetName(), err)
	}

	s.logger.DebugContext(ctx, fmt.Sprintf("PolicyReport %s", operation),
		slog.String("report-name", policyReport.GetName()),
		slog.String("report-version", policyReport.GetResourceVersion()),
		slog.String("resource-name", policyReport.Scope.Name),
		slog.String("resource-namespace", policyReport.Scope.Namespace),
		slog.String("resource-version", policyReport.Scope.ResourceVersion))

	return nil
}

// DeleteOldReports deletes all the OpenReports Reports that do not belong to the current scan run.
func (s *OpenReportStore) DeleteOldReports(ctx context.Context, scanRunID, namespace string) error {
	labelSelector, err := labels.Parse(fmt.Sprintf("%s!=%s,%s=%s", auditConstants.AuditScannerRunUIDLabel, scanRunID, labelAppManagedBy, labelApp))
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}
	s.logger.DebugContext(ctx, "Deleting old PolicyReports", slog.String("labelSelector", labelSelector.String()))

	if err := s.client.DeleteAllOf(ctx, &openreports.Report{}, &client.DeleteAllOfOptions{ListOptions: client.ListOptions{
		LabelSelector: labelSelector,
		Namespace:     namespace,
	}}); err != nil {
		return fmt.Errorf("failed to delete PolicyReports: %w", err)
	}
	return nil
}

// CreateOrPatchClusterReport creates or patches a OpenReports ClusterReport.
func (s *OpenReportStore) CreateOrPatchClusterReport(ctx context.Context, obj any) error {
	openReport, ok := obj.(*OpenClusterReport)
	if !ok {
		return fmt.Errorf("expected *OpenReport, got %T", obj)
	}
	clusterPolicyReport := openReport.report
	oldClusterPolicyReport := &openreports.ClusterReport{ObjectMeta: metav1.ObjectMeta{
		Name: clusterPolicyReport.GetName(),
	}}

	operation, err := controllerutil.CreateOrPatch(ctx, s.client, oldClusterPolicyReport, func() error {
		oldClusterPolicyReport.ObjectMeta.Labels = clusterPolicyReport.ObjectMeta.Labels
		oldClusterPolicyReport.ObjectMeta.OwnerReferences = clusterPolicyReport.ObjectMeta.OwnerReferences
		oldClusterPolicyReport.Scope = clusterPolicyReport.Scope
		oldClusterPolicyReport.Summary = clusterPolicyReport.Summary
		oldClusterPolicyReport.Results = clusterPolicyReport.Results

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or patch cluster policy report %s: %w", clusterPolicyReport.GetName(), err)
	}

	s.logger.DebugContext(ctx, fmt.Sprintf("ClusterPolicyReport %s", operation),
		slog.String("report-name", clusterPolicyReport.GetName()),
		slog.String("report-version", clusterPolicyReport.GetResourceVersion()),
		slog.String("resource-name", clusterPolicyReport.Scope.Name),
		slog.String("resource-namespace", clusterPolicyReport.Scope.Namespace),
		slog.String("resource-version", clusterPolicyReport.Scope.ResourceVersion))

	return nil
}

// DeleteOldClusterReports deletes all the OpenReports ClusterReports that do not belong to the current scan run.
func (s *OpenReportStore) DeleteOldClusterReports(ctx context.Context, scanRunID string) error {
	labelSelector, err := labels.Parse(fmt.Sprintf("%s!=%s,%s=%s", auditConstants.AuditScannerRunUIDLabel, scanRunID, labelAppManagedBy, labelApp))
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}
	s.logger.DebugContext(ctx, "Deleting old ClusterPolicyReports", slog.String("labelSelector", labelSelector.String()))

	if err := s.client.DeleteAllOf(ctx, &openreports.ClusterReport{}, &client.DeleteAllOfOptions{ListOptions: client.ListOptions{
		LabelSelector: labelSelector,
	}}); err != nil {
		return fmt.Errorf("failed to delete ClusterPolicyReports: %w", err)
	}
	return nil
}
