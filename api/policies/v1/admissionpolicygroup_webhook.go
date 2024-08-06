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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// log is for logging in this package.
//
//nolint:gochecknoglobals // let's keep the log variable here for now
var admissionpolicygrouplog = logf.Log.WithName("admissionpolicygroup-resource")

func (r *AdmissionPolicyGroup) SetupWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-admissionpolicygroup,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpoliciesgroup,verbs=create;update,versions=v1,name=madmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &AdmissionPolicyGroup{}

// Default implements webhook.Defaulter so a webhook will be registered for the type.
func (r *AdmissionPolicyGroup) Default() {
	admissionpolicygrouplog.Info("default", "name", r.Name)
	if r.Spec.PolicyServer == "" {
		r.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if r.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(r, constants.KubewardenFinalizer)
	}
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-admissionpolicygroup,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=admissionpoliciesgroup,verbs=create;update,versions=v1,name=vadmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &AdmissionPolicyGroup{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (r *AdmissionPolicyGroup) ValidateCreate() (admission.Warnings, error) {
	admissionpolicygrouplog.Info("validate create", "name", r.Name)
	errList := field.ErrorList{}

	if errs := validateRulesField(r); len(errs) != 0 {
		errList = append(errList, errs...)
	}
	if errs := validateMatchConditionsField(r); len(errs) != 0 {
		errList = append(errList, errs...)
	}
	if err := validatePolicyGroupMembers(r); err != nil {
		errList = append(errList, err)
	}
	if len(errList) != 0 {
		return nil, prepareInvalidAPIError(r, errList)
	}
	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (r *AdmissionPolicyGroup) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	admissionpolicygrouplog.Info("validate update", "name", r.Name)

	oldPolicy, ok := old.(*AdmissionPolicyGroup)
	if !ok {
		return admission.Warnings{}, apierrors.NewInternalError(
			fmt.Errorf("object is not of type AdmissionPolicyGroup: %#v", old))
	}
	return nil, validatePolicyUpdate(oldPolicy, r)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (r *AdmissionPolicyGroup) ValidateDelete() (admission.Warnings, error) {
	admissionpolicygrouplog.Info("validate delete", "name", r.Name)
	return nil, nil
}
