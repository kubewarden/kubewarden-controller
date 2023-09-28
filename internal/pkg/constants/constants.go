package constants

// DefaultPolicyServer is set to a non empty value if policies that
// are missing a policy server should be defaulted to this one
// before being persisted.
var DefaultPolicyServer string

const (
	RootCASecretName          = "kubewarden-root-ca"
	ControllerCertsSecretName = "webhook-server-cert" //nolint:gosec
	// PolicyServer CA Secret
	PolicyServerTLSCert                  = "policy-server-cert"
	PolicyServerTLSKey                   = "policy-server-key"
	PolicyServerCARootSecretName         = "policy-server-root-ca"
	PolicyServerCARootPemName            = "policy-server-root-ca-pem"
	PolicyServerCARootCACert             = "policy-server-root-ca-cert"
	PolicyServerCARootPrivateKeyCertName = "policy-server-root-ca-privatekey-cert"

	// PolicyServer Deployment
	PolicyServerEnableMetricsEnvVar                 = "KUBEWARDEN_ENABLE_METRICS"
	PolicyServerDeploymentConfigVersionAnnotation   = "kubewarden/config-version"
	PolicyServerDeploymentPodSpecConfigVersionLabel = "kubewarden/config-version"
	PolicyServerPort                                = 8443
	PolicyServerMetricsPortEnvVar                   = "KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT"
	PolicyServerMetricsPort                         = 8080
	PolicyServerReadinessProbe                      = "/readiness"
	PolicyServerLogFmtEnvVar                        = "KUBEWARDEN_LOG_FMT"

	// PolicyServer ConfigMap
	PolicyServerConfigPoliciesEntry         = "policies.yml"
	PolicyServerDeploymentRestartAnnotation = "kubectl.kubernetes.io/restartedAt"
	PolicyServerConfigSourcesEntry          = "sources.yml"
	PolicyServerSourcesConfigContainerPath  = "/sources"

	// PolicyServer VerificationSecret
	PolicyServerVerificationConfigEntry         = "verification-config"
	PolicyServerVerificationConfigContainerPath = "/verification"

	// Label
	AppLabelKey          = "app"
	PolicyServerLabelKey = "kubewarden/policy-server"

	// Index
	PolicyServerIndexKey = ".spec.policyServer"

	// Finalizers
	KubewardenFinalizer = "kubewarden"

	// Kubernetes
	KubernetesRevisionAnnotation = "deployment.kubernetes.io/revision"

	// OPTEL
	OptelInjectAnnotation = "sidecar.opentelemetry.io/inject"

	// Webhook Configurations
	WebhookConfigurationPolicyScopeLabelKey          = "kubewardenPolicyScope"
	WebhookConfigurationPolicyNameAnnotationKey      = "kubewardenPolicyName"
	WebhookConfigurationPolicyNamespaceAnnotationKey = "kubewardenPolicyNamespace"

	ControllerValidatingWebhookName = "kubewarden-controller-validating-webhook-configuration"
	ControllerMutatingWebhookName   = "kubewarden-controller-mutating-webhook-configuration"
)
