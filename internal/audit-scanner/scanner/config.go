package scanner

import (
	"log/slog"

	"github.com/kubewarden/kubewarden-controller/internal/audit-scanner/k8s"
	"github.com/kubewarden/kubewarden-controller/internal/audit-scanner/policies"
	"github.com/kubewarden/kubewarden-controller/internal/audit-scanner/report"
)

type ParallelizationConfig struct {
	ParallelNamespacesAudits int
	ParallelResourcesAudits  int
	PoliciesAudits           int
}

type TLSConfig struct {
	Insecure       bool
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
}

type Config struct {
	PoliciesClient *policies.Client
	K8sClient      *k8s.Client

	ReportStore report.Store
	ReportKind  report.CrdKind

	TLS             TLSConfig
	Parallelization ParallelizationConfig

	OutputScan   bool
	DisableStore bool

	Logger *slog.Logger
}
