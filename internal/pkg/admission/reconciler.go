package admission

import (
	"context"
	"strings"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubewardenv1alpha1 "github.com/kubewarden/kubewarden-controller/api/v1alpha1"
)

type Reconciler struct {
	Client               client.Client
	DeploymentsNamespace string
	Log                  logr.Logger
}

type errorList []error

func (errorList errorList) Error() string {
	errors := []string{}
	for _, error := range errorList {
		errors = append(errors, error.Error())
	}
	return strings.Join(errors, ", ")
}

func (r *Reconciler) ReconcileDeletion(ctx context.Context,
	clusterAdmissionPolicy *kubewardenv1alpha1.ClusterAdmissionPolicy) error {
	errors := errorList{}
	r.Log.Info("Removing deleted policy from PolicyServer ConfigMap")
	if err := r.reconcilePolicyServerConfigMap(ctx, clusterAdmissionPolicy, RemovePolicy); err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot update ConfigMap")
		errors = append(errors, err)
	}

	r.Log.Info("Removing ValidatingWebhookConfiguration associated with deleted policy")
	validatingWebhookConf := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
		},
	}
	if err := r.Client.Delete(ctx, validatingWebhookConf); err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete ValidatingWebhookConfiguration")
		errors = append(errors, err)
	}

	r.Log.Info("Removing MutatingWebhookConfiguration associated with deleted policy")
	mutatingWebhookConf := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
		},
	}
	if err := r.Client.Delete(ctx, mutatingWebhookConf); err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete MutatingWebhookConfiguration")
		errors = append(errors, err)
	}

	if err := r.reconcilePolicyServerDeployment(ctx); err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot reconcile PolicyServer deployment")
		errors = append(errors, err)
	}
	if len(errors) == 0 {
		return nil
	}

	return errors
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	clusterAdmissionPolicy *kubewardenv1alpha1.ClusterAdmissionPolicy,
) error {
	policyServerSecret, err := r.fetchOrInitializePolicyServerSecret(ctx)
	if err != nil {
		return err
	}
	if err := r.reconcileSecret(ctx, policyServerSecret); err != nil {
		return err
	}
	if err := r.reconcilePolicyServerConfigMap(ctx, clusterAdmissionPolicy, AddPolicy); err != nil {
		return err
	}
	if err := r.reconcilePolicyServerDeployment(ctx); err != nil {
		return err
	}
	if err := r.reconcilePolicyServerService(ctx); err != nil {
		return err
	}

	policyServerReady, err := r.isPolicyServerReady(ctx)
	if policyServerReady {
		// register the new dynamic admission controller only once the policy is
		// served by the PolicyServer deployment
		if clusterAdmissionPolicy.Spec.Mutating {
			return r.reconcileMutatingWebhookRegistration(ctx, clusterAdmissionPolicy, policyServerSecret)
		}

		return r.reconcileValidatingWebhookRegistration(ctx, clusterAdmissionPolicy, policyServerSecret)
	}
	return err
}

func (r *Reconciler) operationTypes(
	clusterAdmissionPolicy *kubewardenv1alpha1.ClusterAdmissionPolicy,
) []admissionregistrationv1.OperationType {
	operationTypes := []admissionregistrationv1.OperationType{}
	for _, operation := range clusterAdmissionPolicy.Spec.Operations {
		switch strings.ToUpper(operation) {
		case "*":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.OperationAll,
			)
		case "CREATE":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Create,
			)
		case "UPDATE":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Update,
			)
		case "DELETE":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Delete,
			)
		case "CONNECT":
			operationTypes = append(
				operationTypes,
				admissionregistrationv1.Connect,
			)
		default:
			continue
		}
	}
	return operationTypes
}
