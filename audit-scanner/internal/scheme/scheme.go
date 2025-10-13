package scheme

import (
	"fmt"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	openreports "github.com/openreports/reports-api/pkg/client/clientset/versioned/scheme"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func NewScheme() (*runtime.Scheme, error) {
	scheme := scheme.Scheme
	err := policiesv1.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to add Kubewarden types into scheme: %w", err)
	}
	err = wgpolicy.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to add policy report types into scheme: %w", err)
	}
	err = openreports.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to add open report types into scheme: %w", err)
	}

	return scheme, nil
}
