package constants

var (
	// DefaultPolicyServer is set to a non empty value if policies that
	// are missing a policy server should be defaulted to this one
	// before being persisted.
	DefaultPolicyServer string
)

const (
	// PolicyServer CA Secret
	PolicyServerTLSCert          = "tls.crt"
	PolicyServerTLSKey           = "tls.key"
	PolicyServerCARootSecretName = "policy-server-root-ca"
	PolicyServerCARootPemName    = "policy-server-root-ca-pem"
	// Root CA secret
	CARootCACert                    = "tls.crt"
	CARootCACertPem                 = "cert-pem"
	CARootPrivateKeyCertName        = "tls.key"
	KubewardenCARootSecretName      = "kubewarden-root-ca"
	ControllerCertificateSecretName = "webhook-server-cert" //nolint:gosec

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
	AppLabelKey                   = "app"
	PolicyServerLabelKey          = "kubewarden/policy-server"
	PolicyServerCertificateSecret = "kubewarden/policy-server-certificate-secret-version" //nolint:gosec

	// Index
	PolicyServerIndexKey = ".spec.policyServer"

	// Finalizers
	KubewardenFinalizer = "kubewarden"

	// Kubernetes
	KubernetesRevisionAnnotation = "deployment.kubernetes.io/revision"

	// OPTEL
	OptelInjectAnnotation = "sidecar.opentelemetry.io/inject"

	ControllerReturnCodeSuccess       = 0
	ControllerReturnCodeError         = 1
	ControllerReturnCodeCAInitialized = 2
)
