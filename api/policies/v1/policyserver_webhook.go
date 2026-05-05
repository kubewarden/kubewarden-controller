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
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/api/validation"
	validationutils "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/go-logr/logr"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// capabilityNode is a node in the host-capability path tree.
// Leaf nodes (complete, addressable operations) have a nil value.
// Intermediate nodes carry a non-nil map of named children.
type capabilityNode map[string]capabilityNode

// capabilityTree is the authoritative tree of all recognised host capability
// paths. It mirrors the namespaces and operations handled by the policy-server
// callback (crates/policy-server/src/evaluation/callback.rs).
//
//nolint:gochecknoglobals // effectively a constant, not used anywhere else
var capabilityTree = capabilityNode{
	"oci": {
		"v1": {
			"verify":              nil,
			"manifest_digest":     nil,
			"oci_manifest":        nil,
			"oci_manifest_config": nil,
		},
		"v2": {
			"verify": nil,
		},
	},
	"net": {
		"v1": {
			"dns_lookup_host": nil,
		},
	},
	"crypto": {
		"v1": {
			"is_certificate_trusted": nil,
		},
	},
	"kubernetes": {
		"list_resources_by_namespace": nil,
		"list_resources_all":          nil,
		"get_resource":                nil,
		"can_i":                       nil,
	},
}

// SetupWebhookWithManager registers the PolicyServer webhook with the controller manager.
func (ps *PolicyServer) SetupWebhookWithManager(mgr ctrl.Manager, deploymentsNamespace string) error {
	logger := mgr.GetLogger().WithName("policyserver-webhook")

	err := ctrl.NewWebhookManagedBy(mgr, ps).
		WithDefaulter(&policyServerDefaulter{
			logger: logger,
		}).
		WithValidator(&policyServerValidator{
			deploymentsNamespace: deploymentsNamespace,
			k8sClient:            mgr.GetClient(),
			logger:               logger,
		}).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}

	return nil
}

// +kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-policyserver,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=policyservers,verbs=create;update,versions=v1,name=mpolicyserver.kb.io,admissionReviewVersions={v1,v1beta1}

// policyServerDefaulter sets defaults of PolicyServer objects when they are created or updated.
type policyServerDefaulter struct {
	logger logr.Logger
}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the type.
func (d *policyServerDefaulter) Default(_ context.Context, policyServer *PolicyServer) error {
	d.logger.Info("Defaulting PolicyServer", "name", policyServer.GetName())

	if policyServer.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(policyServer, constants.KubewardenFinalizer)
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-policies-kubewarden-io-v1-policyserver,mutating=false,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=policyservers,verbs=create;update,versions=v1,name=vpolicyserver.kb.io,admissionReviewVersions=v1

// polyServerCustomValidator validates PolicyServers when they are created, updated, or deleted.
type policyServerValidator struct {
	deploymentsNamespace string
	k8sClient            client.Client
	logger               logr.Logger
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *policyServerValidator) ValidateCreate(ctx context.Context, policyServer *PolicyServer) (admission.Warnings, error) {
	v.logger.Info("Validating PolicyServer create", "name", policyServer.GetName())

	return nil, v.validate(ctx, policyServer)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.)
func (v *policyServerValidator) ValidateUpdate(ctx context.Context, _, policyServer *PolicyServer) (admission.Warnings, error) {
	v.logger.Info("Validating PolicyServer update", "name", policyServer.GetName())

	return nil, v.validate(ctx, policyServer)
}

// ValdidaeDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *policyServerValidator) ValidateDelete(_ context.Context, policyServer *PolicyServer) (admission.Warnings, error) {
	v.logger.Info("Validating PolicyServer delete", "name", policyServer.GetName())

	return nil, nil
}

// validate validates a the fields PolicyServer object.
func (v *policyServerValidator) validate(ctx context.Context, policyServer *PolicyServer) error {
	var allErrs field.ErrorList

	// The PolicyServer name must be maximum 63 like all Kubernetes objects to fit in a DNS subdomain name
	if len(policyServer.GetName()) > validationutils.DNS1035LabelMaxLength {
		allErrs = append(allErrs, field.Invalid(field.NewPath("metadata").Child("name"), policyServer.GetName(), fmt.Sprintf("the PolicyServer name cannot be longer than %d characters", validationutils.DNS1035LabelMaxLength)))
	}

	if policyServer.Spec.ImagePullSecret != "" {
		if err := validateImagePullSecret(ctx, v.k8sClient, policyServer.Spec.ImagePullSecret, v.deploymentsNamespace); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("imagePullSecret"), policyServer.Spec.ImagePullSecret, err.Error()))
		}
	}

	if policyServer.Spec.SigstoreTrustConfig != "" {
		if err := validateSigstoreTrustConfig(ctx, v.k8sClient, policyServer.Spec.SigstoreTrustConfig, v.deploymentsNamespace); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("sigstoreTrustConfig"), policyServer.Spec.SigstoreTrustConfig, err.Error()))
		}
	}

	// Kubernetes does not allow to set both MinAvailable and MaxUnavailable at the same time
	if policyServer.Spec.MinAvailable != nil && policyServer.Spec.MaxUnavailable != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec"), fmt.Sprintf("minAvailable: %s, maxUnavailable: %s", policyServer.Spec.MinAvailable, policyServer.Spec.MaxUnavailable), "minAvailable and maxUnavailable cannot be both set"))
	}

	allErrs = append(allErrs, validateLimitsAndRequests(policyServer.Spec.Limits, policyServer.Spec.Requests)...)
	allErrs = append(allErrs, validateNamespacedPoliciesCapabilities(policyServer.Spec.NamespacedPoliciesCapabilities)...)
	allErrs = append(allErrs, v.validatePorts(policyServer)...)

	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(GroupVersion.WithKind("PolicyServer").GroupKind(), policyServer.Name, allErrs)
}

// validateImagePullSecret validates that the specified PolicyServer imagePullSecret exists and is of type kubernetes.io/dockerconfigjson.
func validateImagePullSecret(ctx context.Context, k8sClient client.Client, imagePullSecret string, deploymentsNamespace string) error {
	secret := &corev1.Secret{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: deploymentsNamespace,
		Name:      imagePullSecret,
	}, secret)
	if err != nil {
		return fmt.Errorf("cannot get spec.imagePullSecret: %w", err)
	}

	if secret.Type != "kubernetes.io/dockerconfigjson" {
		return fmt.Errorf("spec.imagePullSecret secret \"%s\" is not of type kubernetes.io/dockerconfigjson", secret.Name)
	}

	return nil
}

// validateSigstoreTrustConfig validates that the specified PolicyServer sigstoreTrustConfig ConfigMap exists
// and contains the required key.
func validateSigstoreTrustConfig(ctx context.Context, k8sClient client.Client, sigstoreTrustConfig string, deploymentsNamespace string) error {
	configMap := &corev1.ConfigMap{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: deploymentsNamespace,
		Name:      sigstoreTrustConfig,
	}, configMap)
	if err != nil {
		return fmt.Errorf("cannot get spec.sigstoreTrustConfig ConfigMap: %w", err)
	}

	if _, ok := configMap.Data[constants.PolicyServerSigstoreTrustConfigEntry]; !ok {
		return fmt.Errorf("spec.sigstoreTrustConfig ConfigMap \"%s\" does not contain required key \"%s\"", sigstoreTrustConfig, constants.PolicyServerSigstoreTrustConfigEntry)
	}

	return nil
}

// validateLimitsAndRequests validates that the specified PolicyServer limits and requests are not negative and requests are less than or equal to limits.
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

// validateNamespacedPoliciesCapabilities validates each capability pattern
// against the authoritative capability tree.
//
// Valid formats:
//   - "*"                (allow all capabilities)
//   - "category/*"       (e.g. "oci/*", "kubernetes/*")
//   - "category/sub/*"   (e.g. "oci/v1/*")
//   - full path          (e.g. "oci/v1/verify", "kubernetes/can_i")
//
// Every segment is validated against the tree, so unknown categories,
// unknown versions, and unknown operations are all rejected with an error
// listing the valid options at that level.
func validateNamespacedPoliciesCapabilities(capabilities []string) field.ErrorList {
	var allErrs field.ErrorList
	fieldPath := field.NewPath("spec").Child("namespacedPoliciesCapabilities")

	for i, pattern := range capabilities {
		if err := validateSingleCapability(pattern, fieldPath.Index(i)); err != nil {
			allErrs = append(allErrs, err)
		}
	}
	return allErrs
}

// validateSingleCapability validates one capability pattern against the capability tree.
func validateSingleCapability(pattern string, path *field.Path) *field.Error {
	if pattern == "" {
		return field.Invalid(path, pattern, "capability must not be empty")
	}
	if pattern == "*" {
		return nil
	}

	parts := strings.Split(pattern, "/")
	node := capabilityTree

	for i, part := range parts {
		// Wildcard handling: "*" is only valid as the final segment.
		if strings.Contains(part, "*") {
			if part != "*" || i != len(parts)-1 {
				return field.Invalid(path, pattern,
					"wildcard \"*\" is only allowed as the last path segment (e.g. \"oci/*\" or \"oci/v1/*\")")
			}
			// Valid wildcard termination; parent node is already confirmed.
			return nil
		}

		child, found := node[part]
		if !found {
			return field.Invalid(path, pattern,
				fmt.Sprintf("unknown segment %q, valid options at this level are: %s",
					part, strings.Join(slices.Sorted(maps.Keys(node)), ", ")))
		}

		if child == nil {
			// Leaf reached, path must end here.
			if i != len(parts)-1 {
				return field.Invalid(path, pattern,
					fmt.Sprintf("%q is a complete capability path and cannot have further segments",
						strings.Join(parts[:i+1], "/")))
			}
			return nil
		}

		node = child
	}

	// Consumed all parts but stopped at an intermediate node: the path is
	// incomplete. Guide the user toward the wildcard form.
	return field.Invalid(path, pattern,
		fmt.Sprintf("%q is not a complete capability path; use %q to allow all capabilities under it",
			pattern, pattern+"/*"))
}

// validatePorts checks that the port fields in the PolicyServer spec do not
// conflict with each other. Only pod-side ports (webhookPort, readinessProbePort)
// are validated against each other. spec.metricsPort is a Service-layer-only
// setting and cannot conflict with pod-side ports.
func (v *policyServerValidator) validatePorts(policyServer *PolicyServer) field.ErrorList {
	var allErrs field.ErrorList

	webhookPort := policyServer.EffectiveWebhookPort()
	readinessPort := policyServer.EffectiveReadinessProbePort()

	if webhookPort == readinessPort {
		allErrs = append(allErrs, field.Invalid(
			field.NewPath("spec").Child("readinessProbePort"),
			readinessPort,
			fmt.Sprintf("readinessProbePort must differ from webhookPort (%d)", webhookPort),
		))
	}

	return allErrs
}
