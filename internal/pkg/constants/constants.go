package constants

const (
	AdmissionCertSecretKeyName = "admission-cert"
	AdmissionKeySecretKeyName  = "admission-key"
	AdmissionCASecretKeyName   = "admission-ca"

	PolicyServerReplicaSizeKey             = "replicas"
	PolicyServerReplicaSize                = 1
	PolicyServerImageKey                   = "image"
	PolicyServerImage                      = "ghcr.io/chimera-kube/policy-server:latest"
	PolicyServerServiceName                = "policy-server"
	PolicyServerConfigMapName              = "policy-server"
	PolicyServerConfigPoliciesEntry        = "policies.yml"
	PolicyServerDeploymentName             = "policy-server"
	PolicyServerSecretName                 = "policy-server-certs"
	PolicyServerDeploymentConfigAnnotation = "config/version"
	PolicyServerPort                       = 8443
	PolicyServerReadinessProbe             = "/readiness"
)

var (
	AdmissionLabels = map[string]string{"app": "chimera-admission"}
)
