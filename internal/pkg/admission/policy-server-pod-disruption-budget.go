package admission

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *Reconciler) reconcilePolicyServerPodDisruptionBudget(ctx context.Context, policyServer *policiesv1.PolicyServer) error {
	if policyServer.Spec.MinAvailable != nil || policyServer.Spec.MaxUnavailable != nil {
		return reconcilePodDisruptionBudget(ctx, policyServer, r.Client, r.DeploymentsNamespace)
	}
	return deletePodDisruptionBudget(ctx, policyServer, r.Client, r.DeploymentsNamespace)
}

func deletePodDisruptionBudget(ctx context.Context, policyServer *policiesv1.PolicyServer, k8s client.Client, namespace string) error {
	pdb := &k8spoliciesv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildPodDisruptionBudgetName(policyServer),
			Namespace: namespace,
		},
	}
	err := client.IgnoreNotFound(k8s.Delete(ctx, pdb))
	if err != nil {
		err = errors.Join(fmt.Errorf("failed to delete PodDisruptionBudget"), err)
	}
	return err
}

func buildPodDisruptionBudgetName(policyServer *policiesv1.PolicyServer) string {
	return policyServer.NameWithPrefix() + "-pdb"
}

func reconcilePodDisruptionBudget(ctx context.Context, policyServer *policiesv1.PolicyServer, k8s client.Client, namespace string) error {
	pdb := &k8spoliciesv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildPodDisruptionBudgetName(policyServer),
			Namespace: namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, k8s, pdb, func() error {
		pdb.Name = buildPodDisruptionBudgetName(policyServer)
		pdb.Namespace = namespace
		pdb.OwnerReferences = []metav1.OwnerReference{
			*metav1.NewControllerRef(policyServer, policiesv1.GroupVersion.WithKind("PolicyServer")),
		}
		pdb.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{
				constants.AppLabelKey:          policyServer.AppLabel(),
				constants.PolicyServerLabelKey: policyServer.GetName(),
			},
		}
		if policyServer.Spec.MinAvailable != nil {
			pdb.Spec.MinAvailable = policyServer.Spec.MinAvailable
		} else {
			pdb.Spec.MaxUnavailable = policyServer.Spec.MaxUnavailable
		}
		return nil
	})
	if err != nil {
		err = errors.Join(fmt.Errorf("failed to create or update PodDisruptionBudget"), err)
	}
	return err
}
