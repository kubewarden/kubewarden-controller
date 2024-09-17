package constants

import "errors"

const (
	KubewardenPoliciesGroup                   = "policies.kubewarden.io"
	KubewardenPoliciesVersion                 = "v1"
	KubewardenKindClusterAdmissionPolicy      = "ClusterAdmissionPolicy"
	KubewardenKindClusterAdmissionPolicyGroup = "ClusterAdmissionPolicyGroup"
	KubewardenKindAdmissionPolicy             = "AdmissionPolicy"
	KubewardenKindAdmissionPolicyGroup        = "AdmissionPolicyGroup"
	DefaultClusterwideReportName              = "clusterwide"
	AuditScannerRunUIDLabel                   = "kubewarden.io/audit-scanner-run-uid"
)

// ErrResourceNotFound is an error used to tell that the required resource is not found.
var ErrResourceNotFound = errors.New("resource not found")
