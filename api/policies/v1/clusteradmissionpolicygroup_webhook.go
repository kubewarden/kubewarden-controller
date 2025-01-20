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

func (r *ClusterAdmissionPolicyGroup) SetupWebhookWithManager(mgr ctrl.Manager) error {
	logger := mgr.GetLogger().WithName("clusteradmissionpolicygroup-webhook")

	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(&clusterAdmissionPolicyGroupDefaulter{
			logger: logger,
		}).
		WithValidator(&clusterAdmissionPolicyGroupValidator{
			logger: logger,
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}

	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-clusteradmissionpolicygroup,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicygroups,verbs=create;update,versions=v1,name=mclusteradmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

// clusterAdmissionPolicyGroupDefaulter sets default values of ClusterAdmissionPolicyGroup objects when they are created or updated.
type clusterAdmissionPolicyGroupDefaulter struct {
	logger logr.Logger
}

var _ webhook.CustomDefaulter = &clusterAdmissionPolicyGroupDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the type.
func (d *clusterAdmissionPolicyGroupDefaulter) Default(_ context.Context, obj runtime.Object) error {
	clusterAdmissionPolicyGroup, ok := obj.(*ClusterAdmissionPolicyGroup)
	if !ok {
		return fmt.Errorf("expected a ClusterAdmissionPolicyGroup object, got %T", obj)
	}

	d.logger.Info("Defaulting ClusterAdmissionPolicyGroup", "name", clusterAdmissionPolicyGroup.GetName())

	if clusterAdmissionPolicyGroup.Spec.PolicyServer == "" {
		clusterAdmissionPolicyGroup.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if clusterAdmissionPolicyGroup.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(clusterAdmissionPolicyGroup, constants.KubewardenFinalizer)
	}

	return nil
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-clusteradmissionpolicygroup,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicygroups,verbs=create;update,versions=v1,name=vclusteradmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

// clusterAdmissionPolicyGroupValidator validates ClusterAdmissionPolicyGroup objects when they are created, updated, or deleted.
type clusterAdmissionPolicyGroupValidator struct {
	logger logr.Logger
}

var _ webhook.CustomValidator = &clusterAdmissionPolicyGroupValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *clusterAdmissionPolicyGroupValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	clusterAdmissionPolicyGroup, ok := obj.(*ClusterAdmissionPolicyGroup)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterAdmissionPolicyGroup object, got %T", obj)
	}

	v.logger.Info("Validating ClusterAdmissionPolicyGroup creation", "name", clusterAdmissionPolicyGroup.GetName())

	allErrors := validatePolicyGroupCreate(clusterAdmissionPolicyGroup)
	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(clusterAdmissionPolicyGroup, allErrors)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *clusterAdmissionPolicyGroupValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldclusterAdmissionPolicyGroup, ok := oldObj.(*ClusterAdmissionPolicyGroup)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterAdmissionPolicyGroup object, got %T", oldObj)
	}
	newclusterAdmissionPolicyGroup, ok := newObj.(*ClusterAdmissionPolicyGroup)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterAdmissionPolicyGroup object, got %T", newObj)
	}

	v.logger.Info("Validating ClusterAdmissionPolicyGroup update", "name", newclusterAdmissionPolicyGroup.GetName())

	if allErrors := validatePolicyGroupUpdate(oldclusterAdmissionPolicyGroup, newclusterAdmissionPolicyGroup); len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(newclusterAdmissionPolicyGroup, allErrors)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *clusterAdmissionPolicyGroupValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}
