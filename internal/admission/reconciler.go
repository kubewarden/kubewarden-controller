package admission

import (
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Reconciler struct {
	Client               client.Client
	APIReader            client.Reader
	DeploymentsNamespace string
	Log                  logr.Logger
}
