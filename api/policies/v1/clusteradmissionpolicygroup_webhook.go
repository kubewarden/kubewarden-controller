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

	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// log is for logging in this package.
//
//nolint:gochecknoglobals // let's keep the log variable here for now
var clusteradmissionpolicygrouplog = logf.Log.WithName("clusteradmissionpolicygroup-resource")

func (r *ClusterAdmissionPolicyGroup) SetupWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-clusteradmissionpolicygroup,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicygroups,verbs=create;update,versions=v1,name=mclusteradmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ClusterAdmissionPolicyGroup{}

// Default implements webhook.Defaulter so a webhook will be registered for the type.
func (r *ClusterAdmissionPolicyGroup) Default() {
	clusteradmissionpolicygrouplog.Info("default", "name", r.Name)
	if r.Spec.PolicyServer == "" {
		r.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if r.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(r, constants.KubewardenFinalizer)
	}
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-clusteradmissionpolicygroup,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicygroups,verbs=create;update,versions=v1,name=vclusteradmissionpolicygroup.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ClusterAdmissionPolicyGroup{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (r *ClusterAdmissionPolicyGroup) ValidateCreate() (admission.Warnings, error) {
	clusteradmissionpolicygrouplog.Info("validate create", "name", r.Name)

	allErrors := validatePolicyGroupCreate(r)
	if len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(r, allErrors)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (r *ClusterAdmissionPolicyGroup) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	clusteradmissionpolicygrouplog.Info("validate update", "name", r.Name)

	oldPolicy, ok := old.(*ClusterAdmissionPolicyGroup)
	if !ok {
		return admission.Warnings{}, apierrors.NewInternalError(
			fmt.Errorf("object is not of type ClusterAdmissionPolicyGroup: %#v", old))
	}

	if allErrors := validatePolicyGroupUpdate(oldPolicy, r); len(allErrors) != 0 {
		return nil, prepareInvalidAPIError(r, allErrors)
	}

	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (r *ClusterAdmissionPolicyGroup) ValidateDelete() (admission.Warnings, error) {
	clusteradmissionpolicygrouplog.Info("validate delete", "name", r.Name)
	return nil, nil
}
