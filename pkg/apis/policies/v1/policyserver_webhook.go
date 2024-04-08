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
	"errors"
	"fmt"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/policyserver"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	validationutils "k8s.io/apimachinery/pkg/util/validation"
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

	// Default the requests to the limits if not set
	for limitName, limitQuantity := range ps.Spec.Limits {
		if _, found := ps.Spec.Requests[limitName]; !found {
			if ps.Spec.Requests == nil {
				ps.Spec.Requests = make(corev1.ResourceList)
			}
			ps.Spec.Requests[limitName] = limitQuantity
		}
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

	// The PolicyServer name must be maximum 63 like all Kubernetes objects to fit in a DNS subdomain name
	if len(policyServer.GetName()) > validationutils.DNS1035LabelMaxLength {
		return fmt.Errorf("the PolicyServer name cannot be longer than %d characters", validationutils.DNS1035LabelMaxLength)
	}

	if policyServer.Spec.ImagePullSecret != "" {
		err := policyserver.ValidateImagePullSecret(ctx, v.k8sClient, policyServer.Spec.ImagePullSecret, v.deploymentsNamespace)
		if err != nil {
			return fmt.Errorf("spec.ImagePullSecret is invalid: %w", err)
		}
	}

	// Kubernetes does not allow to set both MinAvailable and MaxUnavailable at the same time
	if policyServer.Spec.MinAvailable != nil && policyServer.Spec.MaxUnavailable != nil {
		return errors.New("minAvailable and maxUnavailable cannot be both set")
	}

	err := validateLimitsAndRequests(policyServer.Spec.Limits, policyServer.Spec.Requests)
	if err != nil {
		return err
	}

	return nil
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

func validateLimitsAndRequests(limits, requests corev1.ResourceList) error {
	if requests == nil || limits == nil {
		return nil
	}

	for limitName, limitQuantity := range limits {
		if limitQuantity.Cmp(resource.Quantity{}) < 0 {
			return fmt.Errorf("%s limit must be greater than or equal to 0", limitName)
		}
	}

	for requestName, requestQuantity := range requests {
		if requestQuantity.Cmp(resource.Quantity{}) < 0 {
			return fmt.Errorf("%s request must be greater than or equal to 0", requestName)
		}

		limitQuantity, ok := limits[requestName]
		if !ok {
			continue
		}

		if requestQuantity.Cmp(limitQuantity) > 0 {
			return fmt.Errorf("request must be less than or equal to %s limit", requestName)
		}
	}
	return nil
}
