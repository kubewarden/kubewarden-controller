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

package v1alpha2

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

// log is for logging in this package.
var clusteradmissionpolicylog = logf.Log.WithName("clusteradmissionpolicy-resource")

func (r *ClusterAdmissionPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1alpha2-clusteradmissionpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=create;update,versions=v1alpha2,name=mclusteradmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ClusterAdmissionPolicy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) Default() {
	clusteradmissionpolicylog.Info("default", "name", r.Name)
	if r.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(r, constants.KubewardenFinalizer)
	}
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1alpha2-clusteradmissionpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=create;update,versions=v1alpha2,name=vclusteradmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ClusterAdmissionPolicy{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) ValidateCreate() error {
	clusteradmissionpolicylog.Info("validate create", "name", r.Name)
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) ValidateUpdate(old runtime.Object) error {
	clusteradmissionpolicylog.Info("validate update", "name", r.Name)

	oldPolicy, ok := old.(*ClusterAdmissionPolicy)
	if !ok {
		return apierrors.NewInternalError(
			fmt.Errorf("object is not of type ClusterAdmissionPolicy: %#v", old))
	}

	return validatePolicyUpdate(oldPolicy, r)
}

func validatePolicyUpdate(oldPolicy, newPolicy Policy) error {
	if newPolicy.GetPolicyServer() != oldPolicy.GetPolicyServer() {
		var errs field.ErrorList
		p := field.NewPath("spec")
		pp := p.Child("policyServer")
		errs = append(errs, field.Forbidden(pp, "the field is immutable"))

		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "ClusterAdmissionPolicy"},
			newPolicy.GetName(), errs)
	}
	if newPolicy.GetPolicyMode() == "monitor" && oldPolicy.GetPolicyMode() == "protect" {
		var errs field.ErrorList
		p := field.NewPath("spec")
		pp := p.Child("mode")
		errs = append(errs, field.Forbidden(pp, "field cannot transition from protect to monitor. Recreate instead."))

		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "ClusterAdmissionPolicy"},
			newPolicy.GetName(), errs)
	}

	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) ValidateDelete() error {
	clusteradmissionpolicylog.Info("validate delete", "name", r.Name)
	return nil
}
