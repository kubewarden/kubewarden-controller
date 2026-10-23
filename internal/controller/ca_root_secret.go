package controller

import (
	"bytes"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kubewarden/adm-controller/internal/certs"
)

// caRootSecretPredicate returns a predicate that passes the events of the CA root secret that can change the CA
// bundle of a webhook configuration: the creation of the secret, and an update that changes its CA bundle.
// A deletion does not pass: without the secret there is no bundle to write, and the creation of the secret
// starts the reconcile again.
func caRootSecretPredicate(namespace, name string) predicate.Funcs {
	isCARootSecret := func(object client.Object) bool {
		return object.GetNamespace() == namespace && object.GetName() == name
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isCARootSecret(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if !isCARootSecret(e.ObjectNew) {
				return false
			}
			oldSecret, ok := e.ObjectOld.(*corev1.Secret)
			if !ok {
				return false
			}
			newSecret, ok := e.ObjectNew.(*corev1.Secret)
			if !ok {
				return false
			}
			return !bytes.Equal(certs.CABundleFromSecret(oldSecret), certs.CABundleFromSecret(newSecret))
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}
