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

// This linter directive is added to avoid issues with the
// admissionpolicy_webhook.go file.
//
//nolint:dupl
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

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-clusteradmissionpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=create;update,versions=v1,name=mclusteradmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ClusterAdmissionPolicy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) Default() {
	clusteradmissionpolicylog.Info("default", "name", r.Name)
	if r.Spec.PolicyServer == "" {
		r.Spec.PolicyServer = constants.DefaultPolicyServer
	}
	if r.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(r, constants.KubewardenFinalizer)
	}
}

//+kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-clusteradmissionpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=clusteradmissionpolicies,verbs=create;update,versions=v1,name=vclusteradmissionpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ClusterAdmissionPolicy{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) ValidateCreate() (admission.Warnings, error) {
	clusteradmissionpolicylog.Info("validate create", "name", r.Name)

	return nil, validateRulesField(r)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	clusteradmissionpolicylog.Info("validate update", "name", r.Name)

	oldPolicy, ok := old.(*ClusterAdmissionPolicy)
	if !ok {
		return admission.Warnings{}, apierrors.NewInternalError(
			fmt.Errorf("object is not of type ClusterAdmissionPolicy: %#v", old))
	}

	return nil, validatePolicyUpdate(oldPolicy, r)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ClusterAdmissionPolicy) ValidateDelete() (admission.Warnings, error) {
	clusteradmissionpolicylog.Info("validate delete", "name", r.Name)
	return nil, nil
}
