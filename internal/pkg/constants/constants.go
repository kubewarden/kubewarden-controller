package constants

const (
	// PolicyServer Secret
	PolicyServerTLSCert         = "policy-server-cert"
	PolicyServerTLSKey          = "policy-server-key"
	PolicyServerCASecretKeyName = "policy-server-ca"

	// PolicyServer Deployment
	PolicyServerDeploymentConfigAnnotation = "config/version"
	PolicyServerDeploymentName             = "policy-server"
	PolicyServerImage                      = "ghcr.io/chimera-kube/policy-server:latest"
	PolicyServerImageKey                   = "image"
	PolicyServerPort                       = 8443
	PolicyServerReadinessProbe             = "/readiness"
	PolicyServerReplicaSize                = 1
	PolicyServerReplicaSizeKey             = "replicas"
	PolicyServerSecretName                 = "policy-server-certs"

	// PolicyServer Service
	PolicyServerServiceName = "policy-server"

	// PolicyServer ConfigMap
	PolicyServerConfigMapName       = "policy-server"
	PolicyServerConfigPoliciesEntry = "policies.yml"
)

var (
	PolicyServerLabels = map[string]string{"app": "chimera-policy-server"}
)
