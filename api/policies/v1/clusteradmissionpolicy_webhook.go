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

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// SetupWebhookWithManager registers the ClusterAdmissionPolicy webhook with the controller manager.
func (r *ClusterAdmissionPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	logger := mgr.GetLogger().WithName("clusteradmissionpolicy-webhook")

	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(&clusterAdmissionPolicyDefaulter{
			logger: logger,
		}).
		WithValidator(&clusterAdmissionPolicyValidator{
			logger: logger,
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}

	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-clusteradmissionpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=create;update,versions=v1,name=mclusteradmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

// clusterAdmissionPolicyDefaulter sets default values of ClusterAdmissionPolicy objects when they are created or updated.
type clusterAdmissionPolicyDefaulter struct {
	logger logr.Logger
}

var _ webhook.CustomDefaulter = &clusterAdmissionPolicyDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the type.
func (d *clusterAdmissionPolicyDefaulter) Default(_ context.Context, obj runtime.Object) error {
	clusterAdmissionPolicy, ok := obj.(*ClusterAdmissionPolicy)
	if !ok {
		return fmt.Errorf("expected a ClusterAdmissionPolicy object, got %T", obj)
	}

	d.logger.Info("Defaulting ClusterAdmissionPolicy", "name", clusterAdmissionPolicy.GetName())

	if clusterAdmissionPolicy.Spec.PolicyServer == "" {
		clusterAdmissionPolicy.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if clusterAdmissionPolicy.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(clusterAdmissionPolicy, constants.KubewardenFinalizer)
	}

	return nil
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-clusteradmissionpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=create;update,versions=v1,name=vclusteradmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

// clusterAdmissionPolicyValidator validates ClusterAdmissionPolicy objects when they are created, updated, or deleted.
type clusterAdmissionPolicyValidator struct {
	logger logr.Logger
}

var _ webhook.CustomValidator = &clusterAdmissionPolicyValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *clusterAdmissionPolicyValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	clusterAdmissionPolicy, ok := obj.(*ClusterAdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterAdmissionPolicy object, got %T", obj)
	}

	v.logger.Info("Validating ClusterAdmissionPolicy creation", "name", clusterAdmissionPolicy.GetName())

	allErrors := validatePolicyCreate(clusterAdmissionPolicy)
	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(clusterAdmissionPolicy, allErrors)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *clusterAdmissionPolicyValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldClusterAdmissionPolicy, ok := oldObj.(*ClusterAdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterAdmissionPolicy object, got %T", oldObj)
	}
	newClusterAdmissionPolicy, ok := newObj.(*ClusterAdmissionPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterAdmissionPolicy object, got %T", newObj)
	}

	v.logger.Info("Validating ClusterAdmissionPolicy update", "name", newClusterAdmissionPolicy.GetName())

	allErrors := validatePolicyUpdate(oldClusterAdmissionPolicy, newClusterAdmissionPolicy)
	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(newClusterAdmissionPolicy, allErrors)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *clusterAdmissionPolicyValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}
