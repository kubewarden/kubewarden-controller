package constants

const (
	// PolicyServer Secret
	PolicyServerTLSCert                  = "policy-server-cert"
	PolicyServerTLSKey                   = "policy-server-key"
	PolicyServerCARootSecretName         = "policy-server-root-ca"
	PolicyServerCARootPemName            = "policy-server-root-ca-pem"
	PolicyServerCARootCACert             = "policy-server-root-ca-cert"
	PolicyServerCARootPrivateKeyCertName = "policy-server-root-ca-privatekey-cert"

	// PolicyServer Deployment
	PolicyServerEnableMetricsEnvVar        = "KUBEWARDEN_ENABLE_METRICS"
	PolicyServerDeploymentConfigAnnotation = "config/version"
	PolicyServerPort                       = 8443
	PolicyServerMetricsPortEnvVar          = "KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT"
	PolicyServerMetricsPort                = 8080
	PolicyServerReadinessProbe             = "/readiness"

	// PolicyServer ConfigMap
	PolicyServerConfigPoliciesEntry         = "policies.yml"
	PolicyServerDeploymentRestartAnnotation = "kubectl.kubernetes.io/restartedAt"
	PolicyServerConfigSourcesEntry          = "sources.yml"
	PolicyServerSourcesConfigContainerPath  = "/sources"

	// Label
	AppLabelKey = "app"

	// Index
	PolicyServerIndexKey  = "policyServer"
	PolicyServerIndexName = "name"

	// Finalizers
	KubewardenFinalizer = "kubewarden"
)
