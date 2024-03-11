package report

const (
	policyReportSource            = "kubewarden"
	propertyPolicyResourceVersion = "policy-resource-version"
	propertyPolicyUID             = "policy-uid"
)

const (
	// Status specifies state of a policy result
	statusPass  = "pass"
	statusFail  = "fail"
	statusWarn  = "warn"
	statusError = "error"
	statusSkip  = "skip"
)

const (
	// Severity specifies severity of a policy result
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
	severityInfo     = "info"
)

const (
	// Category specifies the category of a policy result
	typeMutating     = "mutating"
	typeValidating   = "validating"
	typeContextAware = "context-aware"
	valueTypeTrue    = "true"
)

const (
	labelAppManagedBy = "app.kubernetes.io/managed-by"
	labelApp          = "kubewarden"
)
