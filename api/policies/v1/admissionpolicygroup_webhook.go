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

// SetupWebhookWithManager registers the AdmissionPolicyGroup webhook with the controller manager.
func (r *AdmissionPolicyGroup) SetupWebhookWithManager(mgr ctrl.Manager) error {
	logger := mgr.GetLogger().WithName("admissionpolicygroup-webhook")

	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(&admissionPolicyGroupDefaulter{
			logger: logger,
		}).
		WithValidator(&admissionPolicyGroupValidator{
			logger: logger,
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}

	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-admissionpolicygroup,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpolicygroups,verbs=create;update,versions=v1,name=madmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

// admissionPolicyGroupDefaulter sets default values of AdmissionPolicyGroup objects when they are created or updated.
type admissionPolicyGroupDefaulter struct {
	logger logr.Logger
}

var _ webhook.CustomDefaulter = &admissionPolicyGroupDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the type.
func (d *admissionPolicyGroupDefaulter) Default(_ context.Context, obj runtime.Object) error {
	admissionPolicyGroup, ok := obj.(*AdmissionPolicyGroup)
	if !ok {
		return fmt.Errorf("expected an AdmissionPolicyGroup object, got %T", obj)
	}

	d.logger.Info("Defaulting AdmissionPolicyGroup", "name", admissionPolicyGroup.GetName())

	if admissionPolicyGroup.Spec.PolicyServer == "" {
		admissionPolicyGroup.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if admissionPolicyGroup.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(admissionPolicyGroup, constants.KubewardenFinalizer)
	}

	return nil
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-admissionpolicygroup,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpolicygroups,verbs=create;update,versions=v1,name=vadmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

// admissionPolicyGroupValidator validates AdmissionPolicyGroup objects when they are created, updated, or deleted.
type admissionPolicyGroupValidator struct {
	logger logr.Logger
}

var _ webhook.CustomValidator = &admissionPolicyGroupValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *admissionPolicyGroupValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	admissionPolicyGroup, ok := obj.(*AdmissionPolicyGroup)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicyGroup object, got %T", obj)
	}

	v.logger.Info("Validating AdmissionPolicyGroup creation", "name", admissionPolicyGroup.GetName())

	allErrors := validatePolicyGroupCreate(admissionPolicyGroup)

	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(admissionPolicyGroup, allErrors)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (v *admissionPolicyGroupValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldAdmissionPolicyGroup, ok := oldObj.(*AdmissionPolicyGroup)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicyGroup object, got %T", oldObj)
	}
	newAdmissionPolicyGroup, ok := newObj.(*AdmissionPolicyGroup)
	if !ok {
		return nil, fmt.Errorf("expected an AdmissionPolicyGroup object, got %T", newObj)
	}

	v.logger.Info("Validating AdmissionPolicyGroup update", "name", newAdmissionPolicyGroup.GetName())

	if allErrors := validatePolicyGroupUpdate(oldAdmissionPolicyGroup, newAdmissionPolicyGroup); len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(newAdmissionPolicyGroup, allErrors)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *admissionPolicyGroupValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}
