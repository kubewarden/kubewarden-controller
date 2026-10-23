package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/kubewarden/adm-controller/internal/constants"
)

func TestCARootSecretPredicate(t *testing.T) {
	const namespace = "kubewarden"
	caCert := []byte("ca")
	oldCACert := []byte("old-ca")

	newSecret := func(namespace, name string, data map[string][]byte) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Data:       data,
		}
	}
	caRootSecret := func(data map[string][]byte) *corev1.Secret {
		return newSecret(namespace, constants.CARootSecretName, data)
	}

	pred := caRootSecretPredicate(namespace, constants.CARootSecretName)

	t.Run("the creation of the CA root secret passes", func(t *testing.T) {
		require.True(t, pred.Create(event.CreateEvent{Object: caRootSecret(map[string][]byte{constants.CARootCert: caCert})}))
	})

	t.Run("the creation of another secret does not pass", func(t *testing.T) {
		require.False(t, pred.Create(event.CreateEvent{Object: newSecret(namespace, "other", nil)}))
		require.False(t, pred.Create(event.CreateEvent{Object: newSecret("other", constants.CARootSecretName, nil)}))
	})

	updateTests := []struct {
		name     string
		oldData  map[string][]byte
		newData  map[string][]byte
		expected bool
	}{
		{
			name:     "an update that changes the CA certificate passes",
			oldData:  map[string][]byte{constants.CARootCert: caCert},
			newData:  map[string][]byte{constants.CARootCert: []byte("new-ca")},
			expected: true,
		},
		{
			name:     "an update that adds the old CA certificate passes",
			oldData:  map[string][]byte{constants.CARootCert: caCert},
			newData:  map[string][]byte{constants.CARootCert: caCert, constants.OldCARootCert: oldCACert},
			expected: true,
		},
		{
			name:     "an update that removes the old CA certificate passes",
			oldData:  map[string][]byte{constants.CARootCert: caCert, constants.OldCARootCert: oldCACert},
			newData:  map[string][]byte{constants.CARootCert: caCert},
			expected: true,
		},
		{
			name:     "an update that does not change the CA bundle does not pass",
			oldData:  map[string][]byte{constants.CARootCert: caCert, constants.CARootPrivateKey: []byte("key")},
			newData:  map[string][]byte{constants.CARootCert: caCert, constants.CARootPrivateKey: []byte("other-key")},
			expected: false,
		},
	}
	for _, tc := range updateTests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, pred.Update(event.UpdateEvent{
				ObjectOld: caRootSecret(tc.oldData),
				ObjectNew: caRootSecret(tc.newData),
			}))
		})
	}

	t.Run("an update of another secret does not pass", func(t *testing.T) {
		require.False(t, pred.Update(event.UpdateEvent{
			ObjectOld: newSecret(namespace, "other", map[string][]byte{constants.CARootCert: caCert}),
			ObjectNew: newSecret(namespace, "other", map[string][]byte{constants.CARootCert: []byte("new-ca")}),
		}))
	})

	t.Run("the deletion of the CA root secret does not pass", func(t *testing.T) {
		require.False(t, pred.Delete(event.DeleteEvent{Object: caRootSecret(map[string][]byte{constants.CARootCert: caCert})}))
	})
}
