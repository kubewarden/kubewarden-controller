package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/admissionregistration"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/metrics"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
)

type Reconciler struct {
	Client               client.Client
	DeploymentsNamespace string
	Log                  logr.Logger
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
	policyServer *policiesv1alpha2.PolicyServer,
) error {
	errors := reconcilerErrors{}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
		},
	}
	err := r.Client.Delete(ctx, deployment)
	if err != nil && !apierrors.IsNotFound(err) {
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
	if err != nil && !apierrors.IsNotFound(err) {
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
	if err != nil && !apierrors.IsNotFound(err) {
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
	if err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete PolicyServer ConfigMap "+policyServer.Name)
		errors = append(errors, err)
	}

	patch := policyServer.DeepCopy()
	controllerutil.RemoveFinalizer(patch, constants.KubewardenFinalizer)
	err = r.Client.Patch(ctx, patch, client.MergeFrom(policyServer))
	if err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot remove finalizer "+policyServer.Name)
		errors = append(errors, err)
	}
	if len(errors) == 0 {
		return nil
	}

	return errors
}

func setFalseConditionType(
	conditions *[]metav1.Condition,
	conditionType policiesv1alpha2.PolicyConditionType,
	message string,
) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:    string(conditionType),
			Status:  metav1.ConditionFalse,
			Reason:  string(policiesv1alpha2.ReconciliationFailed),
			Message: message,
		},
	)
}

func setTrueConditionType(conditions *[]metav1.Condition, conditionType policiesv1alpha2.PolicyConditionType) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:   string(conditionType),
			Status: metav1.ConditionTrue,
			Reason: string(policiesv1alpha2.ReconciliationSucceeded),
		},
	)
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
) error {
	clusterAdmissionPolicies, err := r.getClusterAdmissionPolicies(ctx, policyServer)
	if err != nil {
		return fmt.Errorf("cannot retrieve cluster admission policies: %w", err)
	}

	err = r.deletePendingClusterAdmissionPolicies(ctx, clusterAdmissionPolicies)
	if err != nil {
		return fmt.Errorf("cannot delete pending cluster admission policies: %w", err)
	}

	policyServerCARootSecret, err := r.fetchOrInitializePolicyServerCARootSecret(ctx, admissionregistration.GenerateCA, admissionregistration.PemEncodeCertificate)
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerCARootSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileSecret(ctx, policyServerCARootSecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerCARootSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerCARootSecretReconciled,
	)

	policyServerSecret, err := r.fetchOrInitializePolicyServerSecret(ctx, policyServer.NameWithPrefix(), policyServerCARootSecret, admissionregistration.GenerateCert)
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileSecret(ctx, policyServerSecret); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	clusterAdmissionPolicies, err = r.getClusterAdmissionPolicies(ctx, policyServer)
	if err != nil {
		return fmt.Errorf("cannot retrieve cluster admission policies: %w", err)
	}

	if err := r.reconcilePolicyServerConfigMap(ctx, policyServer, &clusterAdmissionPolicies); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerConfigMapReconciled,
			fmt.Sprintf("error reconciling configmap: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerConfigMapReconciled,
	)

	if err := r.reconcilePolicyServerDeployment(ctx, policyServer); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerDeploymentReconciled,
			fmt.Sprintf("error reconciling deployment: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerDeploymentReconciled,
	)

	if err := r.reconcilePolicyServerService(ctx, policyServer); err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			policiesv1alpha2.PolicyServerServiceReconciled,
			fmt.Sprintf("error reconciling service: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		policiesv1alpha2.PolicyServerServiceReconciled,
	)

	return r.enablePolicyWebhook(ctx, policyServer, policyServerCARootSecret, &clusterAdmissionPolicies)
}

func (r *Reconciler) HasClusterAdmissionPoliciesBounded(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) (bool, error) {
	clusterAdmissionPolicies, err := r.getClusterAdmissionPolicies(ctx, policyServer)
	if err != nil {
		return false, err
	}
	if len(clusterAdmissionPolicies.Items) > 0 {
		return true, nil
	}

	return false, nil
}

func (r *Reconciler) DeleteAllClusterAdmissionPolicies(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) error {
	clusterAdmissionPolicies, err := r.getClusterAdmissionPolicies(ctx, policyServer)
	if err != nil {
		return err
	}
	for _, policy := range clusterAdmissionPolicies.Items {
		policy := policy // safely use pointer inside for
		// will not delete it because it has a finalizer. It will add a DeletionTimestamp
		err := r.Client.Delete(ctx, &policy)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed deleting pending ClusterAdmissionPolicy %s: %w",
				policy.Name, err)
		}
	}
	err = r.deletePendingClusterAdmissionPolicies(ctx, clusterAdmissionPolicies)
	if err != nil {
		return err
	}
	return nil
}

func (r *Reconciler) enablePolicyWebhook(
	ctx context.Context,
	policyServer *policiesv1alpha2.PolicyServer,
	policyServerSecret *corev1.Secret,
	clusterAdmissionPolicies *policiesv1alpha2.ClusterAdmissionPolicyList) error {
	policyServerReady, err := r.isPolicyServerReady(ctx, policyServer)
	if err != nil {
		return err
	}
	if !policyServerReady {
		return errors.New("policy server not yet ready")
	}

	for _, clusterAdmissionPolicy := range clusterAdmissionPolicies.Items {
		clusterAdmissionPolicy := clusterAdmissionPolicy // safely use pointer inside for
		// register the new dynamic admission controller only once the policy is
		// served by the PolicyServer deployment
		if clusterAdmissionPolicy.Spec.Mutating {
			if err := r.reconcileMutatingWebhookConfiguration(ctx, &clusterAdmissionPolicy, policyServerSecret, policyServer.NameWithPrefix()); err != nil {
				setFalseConditionType(
					&clusterAdmissionPolicy.Status.Conditions,
					policiesv1alpha2.ClusterAdmissionPolicyActive,
					fmt.Sprintf("error reconciling mutating webhook configuration: %v", err),
				)
				return err
			}
		} else {
			if err := r.reconcileValidatingWebhookConfiguration(ctx, &clusterAdmissionPolicy, policyServerSecret, policyServer.NameWithPrefix()); err != nil {
				setFalseConditionType(
					&clusterAdmissionPolicy.Status.Conditions,
					policiesv1alpha2.ClusterAdmissionPolicyActive,
					fmt.Sprintf("error reconciling validating webhook configuration: %v", err),
				)
				return err
			}
		}
		setTrueConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.ClusterAdmissionPolicyActive,
		)
		clusterAdmissionPolicy.Status.PolicyStatus = policiesv1alpha2.ClusterAdmissionPolicyStatusActive
		if err := r.UpdateAdmissionPolicyStatus(ctx, &clusterAdmissionPolicy); err != nil {
			return err
		}
		r.Log.Info("policy " + clusterAdmissionPolicy.Name + " active")
	}

	return nil
}

func (r *Reconciler) getClusterAdmissionPolicies(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) (policiesv1alpha2.ClusterAdmissionPolicyList, error) {
	var clusterAdmissionPolicies policiesv1alpha2.ClusterAdmissionPolicyList
	err := r.Client.List(ctx, &clusterAdmissionPolicies, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name})
	if err != nil {
		err = fmt.Errorf("failed obtaining ClusterAdmissionPolicies: %w", err)
	}
	return clusterAdmissionPolicies, err
}

func (r *Reconciler) deletePendingClusterAdmissionPolicies(ctx context.Context, clusterAdmissionPolicies policiesv1alpha2.ClusterAdmissionPolicyList) error {
	for _, policy := range clusterAdmissionPolicies.Items {
		policy := policy // safely use pointer inside for
		if policy.DeletionTimestamp != nil {
			if policy.Spec.Mutating {
				mutatingWebhook := &admissionregistrationv1.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: policy.Name,
					},
				}
				err := r.Client.Delete(ctx, mutatingWebhook)
				if err != nil && !apierrors.IsNotFound(err) {
					return fmt.Errorf("failed deleting pending ClusterAdmissionPolicy %s: %w",
						policy.Name, err)
				}
			} else {
				validatingWebhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: policy.Name,
					},
				}
				err := r.Client.Delete(ctx, validatingWebhook)
				if err != nil && !apierrors.IsNotFound(err) {
					return fmt.Errorf("failed deleting pending ClusterAdmissionPolicy %s: %w",
						policy.Name, err)
				}
			}
			patch := policy.DeepCopy()
			controllerutil.RemoveFinalizer(patch, constants.KubewardenFinalizer)
			err := r.Client.Patch(ctx, patch, client.MergeFrom(&policy))
			if err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed removing finalizers of ClusterAdmissionPolicy %s: %w",
					policy.Name, err)
			}
		}
	}
	return nil
}

// UpdateAdmissionPolicyStatus Updates the status subresource of the passed
// clusterAdmissionPolicy with a Client apt for it.
func (r *Reconciler) UpdateAdmissionPolicyStatus(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
) error {
	if err := r.Client.Status().Update(ctx, clusterAdmissionPolicy); err != nil {
		return fmt.Errorf("failed to update ClusterAdmissionPolicy %q status", &clusterAdmissionPolicy.ObjectMeta)
	}
	metrics.RecordPolicyCount(clusterAdmissionPolicy)
	return nil
}
