package admission

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

type Reconciler struct {
	Client                                             client.Client
	APIReader                                          client.Reader
	DeploymentsNamespace                               string
	AlwaysAcceptAdmissionReviewsInDeploymentsNamespace bool
	Log                                                logr.Logger
	MetricsEnabled                                     bool
	TracingEnabled                                     bool
}

func setFalseConditionType(
	conditions *[]metav1.Condition,
	conditionType string,
	message string,
) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:    conditionType,
			Status:  metav1.ConditionFalse,
			Reason:  string(policiesv1.ReconciliationFailed),
			Message: message,
		},
	)
}

func setTrueConditionType(conditions *[]metav1.Condition, conditionType string) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:   conditionType,
			Status: metav1.ConditionTrue,
			Reason: string(policiesv1.ReconciliationSucceeded),
		},
	)
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	policyServer *policiesv1.PolicyServer,
	policies []policiesv1.Policy,
) error {
	policyServerCARootSecret, err := r.fetchOrInitializePolicyServerCARootSecret(ctx, policyServer)
	if err != nil {
		return err
	}

	err = r.fetchOrInitializePolicyServerCASecret(ctx, policyServer, policyServerCARootSecret)
	if err != nil {
		return err
	}

	if err := r.reconcilePolicyServerConfigMap(ctx, policyServer, policies); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerConfigMapReconciled),
			fmt.Sprintf("error reconciling configmap: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerConfigMapReconciled),
	)

	if err := r.reconcilePolicyServerPodDisruptionBudget(ctx, policyServer); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerPodDisruptionBudgetReconciled),
			fmt.Sprintf("error reconciling policy server PodDisruptionBudget: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerPodDisruptionBudgetReconciled),
	)

	if err := r.reconcilePolicyServerDeployment(ctx, policyServer); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerDeploymentReconciled),
			fmt.Sprintf("error reconciling deployment: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerDeploymentReconciled),
	)

	if err := r.reconcilePolicyServerService(ctx, policyServer); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerServiceReconciled),
			fmt.Sprintf("error reconciling service: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerServiceReconciled),
	)

	return nil
}

// GetPolicies returns all admission policies and cluster admission
// policies bound to the given policyServer
func (r *Reconciler) GetPolicies(ctx context.Context, policyServer *policiesv1.PolicyServer) ([]policiesv1.Policy, error) {
	var clusterAdmissionPolicies policiesv1.ClusterAdmissionPolicyList
	err := r.Client.List(ctx, &clusterAdmissionPolicies, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name})
	if err != nil && apierrors.IsNotFound(err) {
		err = fmt.Errorf("failed obtaining ClusterAdmissionPolicies: %w", err)
		return nil, err
	}
	var admissionPolicies policiesv1.AdmissionPolicyList
	err = r.Client.List(ctx, &admissionPolicies, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name})
	if err != nil && apierrors.IsNotFound(err) {
		err = fmt.Errorf("failed obtaining ClusterAdmissionPolicies: %w", err)
		return nil, err
	}

	policies := make([]policiesv1.Policy, 0)
	for _, clusterAdmissionPolicy := range clusterAdmissionPolicies.Items {
		policies = append(policies, clusterAdmissionPolicy.DeepCopy())
	}
	for _, admissionPolicy := range admissionPolicies.Items {
		policies = append(policies, admissionPolicy.DeepCopy())
	}

	return policies, nil
}
