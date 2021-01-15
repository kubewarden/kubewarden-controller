package constants

const (
	AdmissionFinalizer         = "chimera/cleanup"
	AdmissionImage             = "ghcr.io/chimera-kube/chimera-admission:latest"
	AdmissionPort              = int32(8443)
	AdmissionPath              = "/validate"
	AdmissionCertSecretKeyName = "admission-cert"
	AdmissionKeySecretKeyName  = "admission-key"
	AdmissionCASecretKeyName   = "admission-ca"
)

var (
	AdmissionLabels = map[string]string{"app": "chimera-admission"}
)
