package admission

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

type reconcilerErrors []error

func (errorList reconcilerErrors) Error() string {
	errors := []string{}
	for _, error := range errorList {
		errors = append(errors, error.Error())
	}
	return strings.Join(errors, ", ")
}

func (r *Reconciler) ReconcileDeletion(
	ctx context.Context,
	policyServer *policiesv1.PolicyServer,
) error {
	errors := reconcilerErrors{}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	err := r.Client.Delete(ctx, deployment)
	if err == nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerDeploymentReconciled),
			"Policy Server has been deleted",
		)
	} else if !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer Deployment "+policyServer.Name)
		errors = append(errors, err)
	}

	certificateSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	err = r.Client.Delete(ctx, certificateSecret)
	if err == nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCASecretReconciled),
			"Policy Server has been deleted",
		)
	} else if !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer Certificate Secret "+policyServer.Name)
		errors = append(errors, err)
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	err = r.Client.Delete(ctx, service)
	if err == nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerServiceReconciled),
			"Policy Server has been deleted",
		)
	} else if !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer Service "+policyServer.Name)
		errors = append(errors, err)
	}

	cfg := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	err = r.Client.Delete(ctx, cfg)
	if err == nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerConfigMapReconciled),
			"Policy Server has been deleted",
		)
	} else if !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer ConfigMap "+policyServer.Name)
		errors = append(errors, err)
	}

	if len(errors) == 0 {
		return nil
	}

	return errors
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
	policyServerCARootSecret, err := r.fetchOrInitializePolicyServerCARootSecret(ctx)
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCARootSecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileCASecret(ctx, policyServerCARootSecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCARootSecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCARootSecretReconciled),
	)

	policyServerCASecret, err := r.fetchOrInitializePolicyServerCASecret(ctx, policyServer.NameWithPrefix(), policyServerCARootSecret)
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCASecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileCASecret(ctx, policyServerCASecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCASecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCASecretReconciled),
	)

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

type GetPoliciesBehavior int

const (
	SkipDeleted GetPoliciesBehavior = iota
	IncludeDeleted
)

// GetPolicies returns all admission policies and cluster admission
// policies bound to the given policyServer
func (r *Reconciler) GetPolicies(ctx context.Context, policyServer *policiesv1.PolicyServer, getPoliciesBehavior GetPoliciesBehavior) ([]policiesv1.Policy, error) {
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
		clusterAdmissionPolicy := clusterAdmissionPolicy
		if getPoliciesBehavior == SkipDeleted && clusterAdmissionPolicy.DeletionTimestamp != nil {
			continue
		}
		policies = append(policies, &clusterAdmissionPolicy)
	}
	for _, admissionPolicy := range admissionPolicies.Items {
		admissionPolicy := admissionPolicy
		if getPoliciesBehavior == SkipDeleted && admissionPolicy.DeletionTimestamp != nil {
			continue
		}
		policies = append(policies, &admissionPolicy)
	}

	return policies, nil
}
