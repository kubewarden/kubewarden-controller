package scheme

import (
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func NewScheme() (*runtime.Scheme, error) {
	scheme := scheme.Scheme
	err := policiesv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = wgpolicy.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}

	return scheme, nil
}
