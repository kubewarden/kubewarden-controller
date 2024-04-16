package admission

import (
	"context"
	"testing"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestPDBCreation(t *testing.T) {
	one := 1
	two := 2
	tests := []struct {
		name           string
		minAvailable   *int
		maxUnavailable *int
	}{
		{"with min value", &two, nil},
		{"with max value", nil, &one},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciler := newReconciler(nil, false)
			policyServer := &policiesv1.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{
					UID:       "uid",
					Name:      "test",
					Namespace: namespace,
				},
			}

			if test.minAvailable != nil {
				minAvailable := intstr.FromInt(*test.minAvailable)
				policyServer.Spec.MinAvailable = &minAvailable
			}
			if test.maxUnavailable != nil {
				maxUnavailable := intstr.FromInt(*test.maxUnavailable)
				policyServer.Spec.MaxUnavailable = &maxUnavailable
			}

			err := reconciler.reconcilePolicyServerPodDisruptionBudget(context.Background(), policyServer)
			require.NoError(t, err)

			pdb := &k8spoliciesv1.PodDisruptionBudget{}
			err = reconciler.Client.Get(context.Background(), client.ObjectKey{
				Namespace: namespace,
				Name:      policyServer.NameWithPrefix(),
			}, pdb)

			require.NoError(t, err)
			assert.Equal(t, policyServer.NameWithPrefix(), pdb.Name)
			assert.Equal(t, policyServer.GetNamespace(), pdb.Namespace)
			if test.minAvailable == nil {
				assert.Nil(t, pdb.Spec.MinAvailable)
			} else {
				assert.Equal(t, intstr.FromInt(*test.minAvailable), *pdb.Spec.MinAvailable)
			}
			if test.maxUnavailable == nil {
				assert.Nil(t, pdb.Spec.MaxUnavailable)
			} else {
				assert.Equal(t, intstr.FromInt(*test.maxUnavailable), *pdb.Spec.MaxUnavailable)
			}
			assert.Equal(t, policyServer.AppLabel(), pdb.Spec.Selector.MatchLabels[constants.AppLabelKey])
			assert.Equal(t, policyServer.GetName(), pdb.Spec.Selector.MatchLabels[constants.PolicyServerLabelKey])
			assert.Equal(t, pdb.OwnerReferences[0].UID, policyServer.UID)
		})
	}
}

func TestPDBUpdate(t *testing.T) {
	one := 1
	two := 2
	eight := 8
	nine := 9
	tests := []struct {
		name              string
		oldMinAvailable   *int
		oldMaxUnavailable *int
		minAvailable      *int
		maxUnavailable    *int
	}{
		{"update min value", nil, nil, &two, nil},
		{"update max value", nil, nil, nil, &one},
		{"update from min to max value", &eight, nil, nil, &one},
		{"update from max to min value", nil, &nine, nil, &one},
		{"update from min to no value", &eight, nil, nil, nil},
		{"update from max to no value", nil, &nine, nil, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyServer := &policiesv1.PolicyServer{
				ObjectMeta: metav1.ObjectMeta{
					UID:       "uid",
					Name:      "test",
					Namespace: namespace,
				},
			}
			if test.minAvailable != nil {
				minAvailable := intstr.FromInt(*test.minAvailable)
				policyServer.Spec.MinAvailable = &minAvailable
			}
			if test.maxUnavailable != nil {
				maxUnavailable := intstr.FromInt(*test.maxUnavailable)
				policyServer.Spec.MaxUnavailable = &maxUnavailable
			}

			oldPDB := &k8spoliciesv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyServer.NameWithPrefix(),
					Namespace: namespace,
				},
				Spec: k8spoliciesv1.PodDisruptionBudgetSpec{
					MinAvailable:   nil,
					MaxUnavailable: nil,
				},
			}
			if test.oldMinAvailable != nil {
				oldPDB.Spec.MinAvailable = &intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: int32(*test.oldMinAvailable),
				}
			}
			if test.oldMaxUnavailable != nil {
				oldPDB.Spec.MaxUnavailable = &intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: int32(*test.oldMaxUnavailable),
				}
			}
			reconciler := newReconciler([]client.Object{oldPDB}, false)
			err := reconciler.reconcilePolicyServerPodDisruptionBudget(context.Background(), policyServer)
			require.NoError(t, err)

			pdb := &k8spoliciesv1.PodDisruptionBudget{}
			err = reconciler.Client.Get(context.Background(), client.ObjectKey{
				Namespace: namespace,
				Name:      policyServer.NameWithPrefix(),
			}, pdb)

			if test.minAvailable == nil && test.maxUnavailable == nil {
				// pdb should be deleted
				require.True(t, apierrors.IsNotFound(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, policyServer.NameWithPrefix(), pdb.Name)
				assert.Equal(t, policyServer.AppLabel(), pdb.Spec.Selector.MatchLabels[constants.AppLabelKey])
				assert.Equal(t, policyServer.GetName(), pdb.Spec.Selector.MatchLabels[constants.PolicyServerLabelKey])
				assert.Equal(t, pdb.OwnerReferences[0].UID, policyServer.UID)
				if test.minAvailable != nil {
					assert.Equal(t, intstr.FromInt(*test.minAvailable), *pdb.Spec.MinAvailable)
				}
				if test.maxUnavailable != nil {
					assert.Equal(t, intstr.FromInt(*test.maxUnavailable), *pdb.Spec.MaxUnavailable)
				}
			}
		})
	}
}

func TestPDBDelete(t *testing.T) {
	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: namespace,
		},
	}
	oldPDB := &k8spoliciesv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: namespace,
		},
		Spec: k8spoliciesv1.PodDisruptionBudgetSpec{
			MinAvailable: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 9,
			},
			MaxUnavailable: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 8,
			},
		},
	}
	reconciler := newReconciler([]client.Object{oldPDB}, false)

	err := reconciler.reconcilePolicyServerPodDisruptionBudget(context.Background(), policyServer)
	require.NoError(t, err)

	pdb := &k8spoliciesv1.PodDisruptionBudget{}
	err = reconciler.Client.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      policyServer.NameWithPrefix(),
	}, pdb)

	require.Error(t, err)
	require.NoError(t, client.IgnoreNotFound(err))
}
