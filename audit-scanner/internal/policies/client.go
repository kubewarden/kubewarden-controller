package policies

import (
	"errors"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newClient() (client.Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		config, err = newConfigFromHomePath()
		if err != nil {
			return nil, err
		}
	}

	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion}, &policiesv1.ClusterAdmissionPolicy{}, &policiesv1.AdmissionPolicy{}, &policiesv1.ClusterAdmissionPolicyList{}, &policiesv1.AdmissionPolicyList{})
	metav1.AddToGroupVersion(customScheme, schema.GroupVersion{Group: kubewardenPoliciesGroup, Version: kubewardenPoliciesVersion})

	return client.New(config, client.Options{Scheme: customScheme})

}

func newConfigFromHomePath() (*rest.Config, error) {
	var kubeConfig string
	if home := homedir.HomeDir(); home != "" {
		kubeConfig = filepath.Join(home, ".kube", "config")
	} else {
		return nil, errors.New("can't get kubeconfig from home dir")
	}

	return clientcmd.BuildConfigFromFlags("", kubeConfig)
}
