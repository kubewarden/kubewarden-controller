package report

import (
	"context"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Store is an interface to abstract the storage of reports. It's agnostic to the
// kind of report used (PolicyReport or OpenReport).
type Store interface {
	CreateOrPatchReport(ctx context.Context, report any) error
	DeleteOldReports(ctx context.Context, scanRunID, namespace string) error
	CreateOrPatchClusterReport(ctx context.Context, report any) error
	DeleteOldClusterReports(ctx context.Context, scanRunID string) error
}

func NewReportStoreOfKind(kind CrdKind, client client.Client, logger *slog.Logger) Store {
	if kind == ReportKindPolicyReport {
		return NewPolicyReportStore(client, logger)
	}
	return NewOpenReportStore(client, logger)
}
