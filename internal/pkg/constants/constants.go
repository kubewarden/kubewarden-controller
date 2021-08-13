//nolint:revive
package constants

const (
	// PolicyServer Secret
	PolicyServerTLSCert                  = "policy-server-cert"
	PolicyServerTLSKey                   = "policy-server-key"
	PolicyServerCARootSecretName         = "policy-server-root-ca"
	PolicyServerCARootPemName            = "policy-server-root-ca-pem"
	PolicyServerCARootPrivateKeyCertName = "policy-server-root-ca-privatekey-cert"

	// PolicyServer Deployment
	PolicyServerDeploymentConfigAnnotation = "config/version"
	PolicyServerDeploymentName             = "policy-server"
	PolicyServerImage                      = "ghcr.io/kubewarden/policy-server:latest"
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
	PolicyServerLabels = map[string]string{"app": "kubewarden-policy-server"}
)
