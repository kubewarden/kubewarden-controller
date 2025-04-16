package constants

import "time"

const (
	// DefaultPolicyServer is the default policy server name to be used when
	// policies does not have a policy server name defined.
	DefaultPolicyServer = "default"

	PolicyServerEnableMetricsEnvVar                 = "KUBEWARDEN_ENABLE_METRICS"
	PolicyServerDeploymentConfigVersionAnnotation   = "kubewarden/config-version"
	PolicyServerDeploymentPodSpecConfigVersionLabel = "kubewarden/config-version"
	PolicyServerPort                                = 8443
	PolicyServerServicePort                         = 443
	PolicyServerMetricsPortEnvVar                   = "KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT"
	PolicyServerMetricsPort                         = 8080
	PolicyServerReadinessProbePort                  = 8081
	PolicyServerReadinessProbe                      = "/readiness"
	PolicyServerLogFmtEnvVar                        = "KUBEWARDEN_LOG_FMT"

	PolicyServerConfigPoliciesEntry         = "policies.yml"
	PolicyServerDeploymentRestartAnnotation = "kubectl.kubernetes.io/restartedAt"
	PolicyServerConfigSourcesEntry          = "sources.yml"
	PolicyServerSourcesConfigContainerPath  = "/sources"

	PolicyServerVerificationConfigEntry         = "verification-config"
	PolicyServerVerificationConfigContainerPath = "/verification"

	// Policy Server Labels.

	AppLabelKey                     = "app"
	PolicyServerLabelKey            = "kubewarden.io/policy-server"
	ComponentPolicyServerLabelValue = "policy-server"
	InstanceLabelKey                = "app.kubernetes.io/instance"
	ComponentLabelKey               = "app.kubernetes.io/component"
	PartOfLabelKey                  = "app.kubernetes.io/part-of"
	PartOfLabelValue                = "kubewarden"
	ManagedByKey                    = "app.kubernetes.io/managed-by"

	PolicyServerIndexKey = ".spec.policyServer"

	KubewardenFinalizerPre114 = "kubewarden"
	KubewardenFinalizer       = "kubewarden.io/finalizer"

	KubernetesRevisionAnnotation = "deployment.kubernetes.io/revision"

	OptelInjectAnnotation = "sidecar.opentelemetry.io/inject"

	WebhookConfigurationPolicyNameAnnotationKey      = "kubewardenPolicyName"
	WebhookConfigurationPolicyNamespaceAnnotationKey = "kubewardenPolicyNamespace"

	NamespacePolicyScope = "namespace"
	ClusterPolicyScope   = "cluster"

	// TimeToRequeuePolicyReconciliation is the Duration to be used when a policy should be reconciliation should be requeued.
	TimeToRequeuePolicyReconciliation = 2 * time.Second
	MetricsShutdownTimeout            = 5 * time.Second

	WebhookServerCertSecretName = "kubewarden-webhook-server-cert" //nolint:gosec // This is not a credential
	ServerCert                  = "tls.crt"
	ServerPrivateKey            = "tls.key"

	CARootSecretName = "kubewarden-ca"
	CARootCert       = "ca.crt"
	CARootPrivateKey = "ca.key"
	OldCARootCert    = "old-ca.crt"

	ClientCACert = "client-ca.crt"

	CertExpirationYears  = 10
	CACertExpiration     = 10 * 365 * 24 * time.Hour
	ServerCertExpiration = 1 * 365 * 24 * time.Hour
	CertLookahead        = 60 * 24 * time.Hour
)
