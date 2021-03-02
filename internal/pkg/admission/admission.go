package admission

import (
	"context"
	"strings"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chimerav1alpha1 "github.com/chimera-kube/chimera-controller/api/v1alpha1"
)

type AdmissionReconciler struct {
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

func (r *AdmissionReconciler) ReconcileDeletion(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	errors := errorList{}
	r.Log.Info("Removing deleted policy from PolicyServer ConfigMap")
	if err := r.reconcilePolicyServerConfigMap(ctx, admissionPolicy, RemovePolicy); err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot update ConfigMap")
		errors = append(errors, err)
	}
	r.Log.Info("Removing ValidatingWebhookConfiguration associated with deleted policy")

	ar := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: admissionPolicy.Name,
		},
	}
	if err := r.Client.Delete(ctx, ar); err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete ValidatingWebhookConfiguration")
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

func (r *AdmissionReconciler) Reconcile(ctx context.Context, admissionPolicy *chimerav1alpha1.AdmissionPolicy) error {
	policyServerSecret, err := r.fetchOrInitializePolicyServerSecret(ctx)
	if err != nil {
		return err
	}
	if err := r.reconcileSecret(ctx, policyServerSecret); err != nil {
		return err
	}
	if err := r.reconcilePolicyServerConfigMap(ctx, admissionPolicy, AddPolicy); err != nil {
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
		return r.reconcileAdmissionRegistration(ctx, admissionPolicy, policyServerSecret)
	}
	return err
}

func (r *AdmissionReconciler) namespace() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.DeploymentsNamespace,
		},
	}
}
