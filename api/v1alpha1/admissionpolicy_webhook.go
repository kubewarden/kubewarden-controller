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

package v1alpha1

import (
	"crypto/sha1"
	"encoding/json"
	"errors"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/chimera-kube/chimera-controller/internal/pkg/constants"
	"github.com/chimera-kube/chimera-controller/internal/pkg/utils"
)

// log is for logging in this package.
var admissionpolicylog = logf.Log.WithName("admissionpolicy-resource")

func (r *AdmissionPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-chimera-suse-com-v1alpha1-admissionpolicy,mutating=true,failurePolicy=fail,groups=chimera.suse.com,resources=admissionpolicies,verbs=create;update,versions=v1alpha1,name=madmissionpolicy.kb.io,sideEffects=none,admissionReviewVersions=v1beta1

var _ webhook.Defaulter = &AdmissionPolicy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *AdmissionPolicy) Default() {
	admissionpolicylog.Info("default", "name", r.Name)

	r.setupFinalizer()
}

func (r *AdmissionPolicy) setupFinalizer() {
	if r.DeletionTimestamp == nil {
		if r.Finalizers == nil {
			r.Finalizers = []string{}
		}
		r.Finalizers = utils.AddStringToSliceIfNotExists(
			constants.AdmissionFinalizer,
			r.Finalizers,
		)
	}
}

// +kubebuilder:webhook:verbs=create;update,path=/validate-chimera-suse-com-v1alpha1-admissionpolicy,mutating=false,failurePolicy=fail,groups=chimera.suse.com,resources=admissionpolicies,versions=v1alpha1,name=madmissionpolicy.kb.io,sideEffects=none,admissionReviewVersions=v1beta1

var _ webhook.Validator = &AdmissionPolicy{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *AdmissionPolicy) ValidateCreate() error {
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *AdmissionPolicy) ValidateUpdate(old runtime.Object) error {
	oldAdmissionPolicy, ok := old.(*AdmissionPolicy)
	if !ok {
		return errors.New("unknown object; rejecting update")
	}
	desiredSpec, err := json.Marshal(r.Spec)
	if err != nil {
		return errors.New("internal error; cannot determine dirtiness of admission policy spec")
	}
	currentSpec, err := json.Marshal(oldAdmissionPolicy.Spec)
	if err != nil {
		return errors.New("internal error; cannot determine dirtiness of admission policy spec")
	}
	if sha1.Sum(currentSpec) != sha1.Sum(desiredSpec) {
		return errors.New("it is not supported to modify policies spec at this time yet; recreate the resource instead")
	}
	// Assume metadata or status change, allow it
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *AdmissionPolicy) ValidateDelete() error {
	return nil
}
