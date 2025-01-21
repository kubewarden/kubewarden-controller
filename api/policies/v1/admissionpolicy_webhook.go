/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/go-logr/logr"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// SetupWebhookWithManager registers the AdmissionPolicy webhook with the controller manager.
func (r *AdmissionPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	logger := mgr.GetLogger().WithName("admissionpolicy-webhook")

	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(&admissionPolicyDefaulter{
			logger: logger,
		}).
		WithValidator(&admissionPolicyValidator{
			logger: logger,
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-admissionpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpolicies,verbs=create;update,versions=v1,name=madmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

// admissionPolicyDefaulter sets default values of AdmissionPolicy objects when they are created or updated.
type admissionPolicyDefaulter struct {
	logger logr.Logger
}

var _ webhook.CustomDefaulter = &admissionPolicyDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the type.
func (d *admissionPolicyDefaulter) Default(_ context.Context, obj runtime.Object) error {
	admissionPolicy, ok := obj.(*AdmissionPolicy)
	if !ok {
		return fmt.Errorf("expected an AdmissionPolicy object, got %T", obj)
	}

	if admissionPolicy.Spec.PolicyServer == "" {
		admissionPolicy.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if admissionPolicy.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(admissionPolicy, constants.KubewardenFinalizer)
	}

	return nil
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-admissionpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpolicies,verbs=create;update,versions=v1,name=vadmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

// admissionPolicyValidator validates AdmissionPolicy objects when they are created, updated, or deleted.
type admissionPolicyValidator struct {
	logger logr.Logger
}

var _ webhook.CustomValidator = &admissionPolicyValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *admissionPolicyValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	admissionPolicy, ok := obj.(*AdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicy object, got %T", obj)
	}

	v.logger.Info("Validating AdmissionPolicy creation", "name", admissionPolicy.GetName())

	allErrors := validatePolicyCreate(admissionPolicy)
	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(admissionPolicy, allErrors)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *admissionPolicyValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldAdmissionPolicy, ok := oldObj.(*AdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicy object, got %T", oldObj)
	}
	newAdmissionPolicy, ok := newObj.(*AdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicy object, got %T", newObj)
	}

	v.logger.Info("Validating ClusterAdmissionPolicy update", "name", newAdmissionPolicy.GetName())

	allErrors := validatePolicyUpdate(oldAdmissionPolicy, newAdmissionPolicy)
	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(newAdmissionPolicy, allErrors)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *admissionPolicyValidator) ValidateDelete(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	admissionPolicy, ok := obj.(*AdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicy object, got %T", obj)
	}

	v.logger.Info("Validating AdmissionPolicy delete", "name", admissionPolicy.GetName())

	return nil, nil
}
