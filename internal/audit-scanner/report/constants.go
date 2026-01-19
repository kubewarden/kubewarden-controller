package report

const (
	policyReportSource            = "kubewarden"
	propertyPolicyResourceVersion = "policy-resource-version"
	propertyPolicyUID             = "policy-uid"
	propertyPolicyName            = "policy-name"
	propertyPolicyNamespace       = "policy-namespace"
)

const (
	// Status specifies state of a policy result.
	statusPass  = "pass"
	statusFail  = "fail"
	statusWarn  = "warn"
	statusError = "error"
	statusSkip  = "skip"
)

const (
	// Severity specifies severity of a policy result.
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
	severityInfo     = "info"
)

const (
	// Category specifies the category of a policy result.
	typeMutating     = "mutating"
	typeValidating   = "validating"
	typeContextAware = "context-aware"
	valueTypeTrue    = "true"
)

const (
	labelAppManagedBy             = "app.kubernetes.io/managed-by"
	labelApp                      = "kubewarden"
	labelPolicyReportVersion      = "kubewarden.io/policyreport-version"
	labelPolicyReportVersionValue = "v2"
)

const (
	OpenReportsKind  = "openreports"
	PolicyReportKind = "policyreport"
)
