package log

import (
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type PolicyReportLogger struct {
}

// LogClusterPolicyReport will create a log line per each cluster-wide scanned resource
func (l *PolicyReportLogger) LogClusterPolicyReport(report *report.ClusterPolicyReport) {
	log.Info().
		Dict("dict", zerolog.Dict().
			Int("pass", report.Summary.Pass).
			Int("fail", report.Summary.Fail).
			Int("warn", report.Summary.Warn).
			Int("error", report.Summary.Error).
			Int("skip", report.Summary.Skip)).
		Msg("ClusterPolicyReport summary")

	for _, result := range report.Results {
		log.Info().
			Dict("dict", zerolog.Dict().
				Str("policy", result.Policy).
				Str("rule", result.Rule).
				Str("result", string(result.Result)).
				Str("message", result.Description).
				// although subjects is a list, there's only 1 element
				Str("resource_api_version", result.Subjects[0].APIVersion).
				Str("resource_kind", result.Subjects[0].Kind).
				Str("resource_namespace", result.Subjects[0].Namespace).
				Str("resource_name", result.Subjects[0].Name).
				Str("resource_version", result.Subjects[0].ResourceVersion)).
			Send()
	}
}

// LogPolicyReport will create a log line per each namespace scanned resource.
func (l *PolicyReportLogger) LogPolicyReport(report *report.PolicyReport) {
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("name", report.GetName()).
			Int("pass", report.Summary.Pass).
			Int("fail", report.Summary.Fail).
			Int("warn", report.Summary.Warn).
			Int("error", report.Summary.Error).
			Int("skip", report.Summary.Skip)).
		Msg("PolicyReport summary")

	for _, result := range report.Results {
		log.Info().
			Dict("dict", zerolog.Dict().
				Str("policy", result.Policy).
				Str("rule", result.Rule).
				Str("result", string(result.Result)).
				Str("message", result.Description).
				// although subjects is a list, there's only 1 element
				Str("resource_api_version", result.Subjects[0].APIVersion).
				Str("resource_kind", result.Subjects[0].Kind).
				Str("resource_namespace", result.Subjects[0].Namespace).
				Str("resource_name", result.Subjects[0].Name).
				Str("resource_version", result.Subjects[0].ResourceVersion)).
			Send()
	}
}
