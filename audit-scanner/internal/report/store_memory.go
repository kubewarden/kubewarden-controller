package report

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// MemoryPolicyReportStore is an implementation of `PolicyReportStore`
// that uses in-memory cache to store `PolicyReports` and `ClusterPolicyReports`
type MemoryPolicyReportStore struct {
	// prCache is a map between a namespace and a PolicyReport
	prCache map[string]PolicyReport

	// cprCache is a map between a name and a ClusterPolicyReport
	cprCache map[string]ClusterPolicyReport
}

func NewMemoryPolicyReportStore() *MemoryPolicyReportStore {
	return &MemoryPolicyReportStore{
		prCache:  make(map[string]PolicyReport),
		cprCache: make(map[string]ClusterPolicyReport),
	}
}

func (s *MemoryPolicyReportStore) GetPolicyReport(namespace string) (PolicyReport, error) {
	report, found := s.prCache[namespace]

	if !found {
		return PolicyReport{}, constants.ErrResourceNotFound
	}

	log.Debug().Dict("dict", zerolog.Dict().
		Str("report name", report.GetName()).
		Str("report ns", report.GetNamespace()).
		Str("report resourceVersion", report.GetResourceVersion())).
		Msg("PolicyReport found")
	return report, nil
}

func (s *MemoryPolicyReportStore) GetClusterPolicyReport(name string) (ClusterPolicyReport, error) {
	if !strings.HasPrefix(name, PrefixNameClusterPolicyReport) {
		name = getClusterReportName(name)
	}

	report, found := s.cprCache[name]
	if !found {
		return ClusterPolicyReport{}, constants.ErrResourceNotFound
	}

	log.Debug().Dict("dict", zerolog.Dict().
		Str("report name", report.GetName()).
		Str("report resourceVersion", report.GetResourceVersion())).
		Msg("ClusterPolicyReport found")
	return report, nil
}

func (s *MemoryPolicyReportStore) updatePolicyReport(report *PolicyReport) error {
	s.prCache[report.GetNamespace()] = *report

	summary, _ := report.GetSummaryJSON()
	log.Debug().Dict("dict", zerolog.Dict().
		Str("report name", report.GetName()).
		Str("report ns", report.GetNamespace()).
		Str("report resourceVersion", report.GetResourceVersion()).
		Str("summary", summary)).
		Msg("updated PolicyReport")
	return nil
}

func (s *MemoryPolicyReportStore) updateClusterPolicyReport(report *ClusterPolicyReport) error {
	s.cprCache[report.GetName()] = *report

	summary, _ := report.GetSummaryJSON()
	log.Debug().Dict("dict", zerolog.Dict().
		Str("report name", report.GetName()).
		Str("report resourceVersion", report.GetResourceVersion()).
		Str("summary", summary)).
		Msg("updated ClusterPolicyReport")
	return nil
}

func (s *MemoryPolicyReportStore) SavePolicyReport(report *PolicyReport) error {
	// Check for existing Policy Report
	_, getErr := s.GetPolicyReport(report.GetNamespace())
	if getErr != nil {
		// Create new Policy Report if not found
		if errors.Is(getErr, constants.ErrResourceNotFound) {
			// Update will create a new one if it doesn't exist
			return s.updatePolicyReport(report)
		}
		return getErr
	}

	// get the latest report version to be updated
	latestReport, err := s.GetPolicyReport(report.GetNamespace())
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	// Update existing Policy Report
	latestReport.Summary = report.Summary
	latestReport.Results = report.Results
	return s.updatePolicyReport(&latestReport)
}

func (s *MemoryPolicyReportStore) SaveClusterPolicyReport(report *ClusterPolicyReport) error {
	// Check for existing Policy Report
	_, getErr := s.GetClusterPolicyReport(report.GetName())
	if getErr != nil {
		// Create new Policy Report if not found
		if errors.Is(getErr, constants.ErrResourceNotFound) {
			// Update will create a new one if it doesn't exist
			return s.updateClusterPolicyReport(report)
		}
		return getErr
	}

	// get the latest report version to be updated
	latestReport, err := s.GetClusterPolicyReport(report.GetName())
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	// Update existing Policy Report
	latestReport.Summary = report.Summary
	latestReport.Results = report.Results
	return s.updateClusterPolicyReport(&latestReport)
}
