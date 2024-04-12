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

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/policyserver"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	validationutils "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var policyserverlog = logf.Log.WithName("policyserver-resource")

func (ps *PolicyServer) SetupWebhookWithManager(mgr ctrl.Manager, deploymentsNamespace string) error {
	err := ctrl.NewWebhookManagedBy(mgr).
		For(ps).
		WithValidator(&policyServerValidator{k8sClient: mgr.GetClient(), deploymentsNamespace: deploymentsNamespace}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

// +kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-policyserver,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=policyservers,verbs=create;update,versions=v1,name=mpolicyserver.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &PolicyServer{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (ps *PolicyServer) Default() {
	policyserverlog.Info("default", "name", ps.Name)
	if ps.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(ps, constants.KubewardenFinalizer)
	}
}

// +kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-policyserver,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=policyservers,verbs=create;update,versions=v1,name=vpolicyserver.kb.io,admissionReviewVersions=v1

// polyServerValidator validates PolicyServers
type policyServerValidator struct {
	k8sClient            client.Client
	deploymentsNamespace string
}

func (v *policyServerValidator) validate(ctx context.Context, obj runtime.Object) error {
	policyServer, ok := obj.(*PolicyServer)
	if !ok {
		return fmt.Errorf("expected a PolicyServer object, got %T", obj)
	}

	var allErrs field.ErrorList

	// The PolicyServer name must be maximum 63 like all Kubernetes objects to fit in a DNS subdomain name
	if len(policyServer.GetName()) > validationutils.DNS1035LabelMaxLength {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata").Child("name"), policyServer.GetName(), fmt.Sprintf("the PolicyServer name cannot be longer than %d characters", validationutils.DNS1035LabelMaxLength)))
	}

	if policyServer.Spec.ImagePullSecret != "" {
		err := policyserver.ValidateImagePullSecret(ctx, v.k8sClient, policyServer.Spec.ImagePullSecret, v.deploymentsNamespace)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("imagePullSecret"), policyServer.Spec.ImagePullSecret, err.Error()))
		}
	}

	// Kubernetes does not allow to set both MinAvailable and MaxUnavailable at the same time
	if policyServer.Spec.MinAvailable != nil && policyServer.Spec.MaxUnavailable != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec"), fmt.Sprintf("minAvailable: %s, maxUnavailable: %s", policyServer.Spec.MinAvailable, policyServer.Spec.MaxUnavailable), "minAvailable and maxUnavailable cannot be both set"))
	}

	allErrs = append(allErrs, validateLimitsAndRequests(policyServer.Spec.Limits, policyServer.Spec.Requests)...)

	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(GroupVersion.WithKind("PolicyServer").GroupKind(), policyServer.Name, allErrs)
}

func (v *policyServerValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, v.validate(ctx, obj)
}

func (v *policyServerValidator) ValidateUpdate(ctx context.Context, _, obj runtime.Object) (admission.Warnings, error) {
	return nil, v.validate(ctx, obj)
}

func (v *policyServerValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func validateLimitsAndRequests(limits, requests corev1.ResourceList) field.ErrorList {
	var allErrs field.ErrorList

	limitFieldPath := field.NewPath("spec").Child("limits")
	requestFieldPath := field.NewPath("spec").Child("requests")

	for limitName, limitQuantity := range limits {
		fieldPath := limitFieldPath.Child(string(limitName))
		if limitQuantity.Cmp(resource.Quantity{}) < 0 {
			allErrs = append(allErrs, field.Invalid(fieldPath, limitQuantity.String(), validation.IsNegativeErrorMsg))
		}
	}

	for requestName, requestQuantity := range requests {
		fieldPath := requestFieldPath.Child(string(requestName))
		if requestQuantity.Cmp(resource.Quantity{}) < 0 {
			allErrs = append(allErrs, field.Invalid(fieldPath, requestQuantity.String(), validation.IsNegativeErrorMsg))
		}

		limitQuantity, ok := limits[requestName]
		if !ok {
			continue
		}

		if requestQuantity.Cmp(limitQuantity) > 0 {
			allErrs = append(allErrs, field.Invalid(fieldPath, requestQuantity.String(), fmt.Sprintf("must be less than or equal to %s limit of %s", requestName, limitQuantity.String())))
		}
	}

	return allErrs
}
