package log

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// ClusterPolicyReport will create a log line per each cluster-wide scanned resource
func ClusterPolicyReport(report *wgpolicy.ClusterPolicyReport) {
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
				Str("resource_api_version", report.Scope.APIVersion).
				Str("resource_kind", report.Scope.Kind).
				Str("resource_namespace", report.Scope.Namespace).
				Str("resource_name", report.Scope.Name).
				Str("resource_version", report.Scope.ResourceVersion)).
			Send()
	}
}

// PolicyReport will create a log line per each namespace scanned resource.
func PolicyReport(report *wgpolicy.PolicyReport) {
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
				Str("resource_api_version", report.Scope.APIVersion).
				Str("resource_kind", report.Scope.Kind).
				Str("resource_namespace", report.Scope.Namespace).
				Str("resource_name", report.Scope.Name).
				Str("resource_version", report.Scope.ResourceVersion)).
			Send()
	}
}
