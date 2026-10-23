package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

const wildcard = "*"

// Reasons why an apiGroup or a resource of the allow list is not valid.
var (
	errAllowListWildcard    = errors.New("wildcards are not permitted")
	errAllowListEmptyItem   = errors.New("empty strings are not permitted")
	errAllowListSubresource = errors.New("subresources are not permitted, list the parent resource instead")
)

// namespacedPoliciesAllowedResources is the list of resources that
// namespaced policies (AdmissionPolicy and AdmissionPolicyGroup) can target.
// A namespaced policy that targets a resource outside of this list is not
// deployed. Cluster-wide policies are not affected.
//
// Each entry is an admissionregistrationv1.Rule, the same type as
// spec.rules[].rule in a policy. The controller reads only the apiGroups
// and resources fields of each entry. It ignores the apiVersions and scope
// fields and logs them.
type namespacedPoliciesAllowedResources []admissionregistrationv1.Rule

// validateNamespacedPoliciesAllowedResources returns the entries of the
// allow list that the controller can use. The function skips and logs each
// item that the controller cannot use:
//   - an apiGroup that contains a wildcard
//   - a resource that is empty, contains a wildcard, or names a subresource
//     (for example "pods/exec")
//
// An entry is skipped only when no valid apiGroup or no valid resource
// remains. The function also logs the apiVersions and scope fields of an
// entry: the controller ignores these fields.
func validateNamespacedPoliciesAllowedResources(entries []admissionregistrationv1.Rule, log logr.Logger) namespacedPoliciesAllowedResources {
	allowed := make(namespacedPoliciesAllowedResources, 0, len(entries))
	for i, entry := range entries {
		logIgnoredFields(entry, i, log)

		apiGroups := make([]string, 0, len(entry.APIGroups))
		for _, apiGroup := range entry.APIGroups {
			if err := validateAPIGroup(apiGroup); err != nil {
				log.Error(err, "skipping an apiGroup of the allow list for namespaced policies",
					"index", i, "apiGroup", apiGroup)
				continue
			}
			apiGroups = append(apiGroups, apiGroup)
		}

		resources := make([]string, 0, len(entry.Resources))
		for _, resource := range entry.Resources {
			if err := validateResource(resource); err != nil {
				log.Error(err, "skipping a resource of the allow list for namespaced policies",
					"index", i, "resource", resource)
				continue
			}
			resources = append(resources, resource)
		}

		switch {
		case len(apiGroups) == 0:
			log.Error(nil, "skipping an entry of the allow list for namespaced policies",
				"index", i, "reason", "apiGroups has no valid item")
			continue
		case len(resources) == 0:
			log.Error(nil, "skipping an entry of the allow list for namespaced policies",
				"index", i, "reason", "resources has no valid item")
			continue
		}

		allowed = append(allowed, admissionregistrationv1.Rule{APIGroups: apiGroups, Resources: resources})
	}

	return allowed
}

// logIgnoredFields logs the fields of an entry that the controller does not
// use. Setting these fields has no effect, so this is information, not an
// error.
func logIgnoredFields(entry admissionregistrationv1.Rule, index int, log logr.Logger) {
	if len(entry.APIVersions) > 0 {
		log.Info("ignoring a field of the allow list for namespaced policies",
			"index", index, "field", "apiVersions", "reason", "the allow list does not use this field")
	}
	if entry.Scope != nil {
		log.Info("ignoring a field of the allow list for namespaced policies",
			"index", index, "field", "scope", "reason", "the allow list does not use this field")
	}
}

// validateAPIGroup returns nil when the apiGroup is valid. The empty string
// names the core API group and is valid.
func validateAPIGroup(apiGroup string) error {
	if strings.Contains(apiGroup, wildcard) {
		return errAllowListWildcard
	}
	return nil
}

// validateResource returns nil when the resource is valid.
func validateResource(resource string) error {
	switch {
	case resource == "":
		return errAllowListEmptyItem
	case strings.Contains(resource, wildcard):
		return errAllowListWildcard
	case strings.Contains(resource, "/"):
		return errAllowListSubresource
	}
	return nil
}

// allows returns true when the allow list contains the given apiGroup and
// resource. The resource can be a subresource (for example "pods/exec" or
// "pods/*"): the parent resource must be in the allow list. A wildcard in
// the apiGroup or in the parent resource never matches.
func (a namespacedPoliciesAllowedResources) allows(apiGroup, resource string) bool {
	if strings.Contains(apiGroup, wildcard) {
		return false
	}

	parentResource, _, _ := strings.Cut(resource, "/")
	if parentResource == "" || strings.Contains(parentResource, wildcard) {
		return false
	}

	for _, entry := range a {
		if slices.Contains(entry.APIGroups, apiGroup) && slices.Contains(entry.Resources, parentResource) {
			return true
		}
	}
	return false
}

// disallowedTargets returns the "resource.group" pairs selected by the
// rules that are not in the allow list. A resource in the core group has no
// group suffix, for example "pods". The result is sorted and has no
// duplicates. An empty result means that all the rules are allowed.
func (a namespacedPoliciesAllowedResources) disallowedTargets(rules []admissionregistrationv1.RuleWithOperations) []string {
	disallowed := []string{}
	for _, rule := range rules {
		for _, apiGroup := range rule.Rule.APIGroups {
			for _, resource := range rule.Rule.Resources {
				if a.allows(apiGroup, resource) {
					continue
				}
				// Name the resource the way kubectl does: "resource.group",
				// or plain "resource" when the group is the core group.
				disallowed = append(disallowed, schema.GroupResource{Group: apiGroup, Resource: resource}.String())
			}
		}
	}

	slices.Sort(disallowed)
	return slices.Compact(disallowed)
}

// isNamespacedPolicyAllowed returns true when the controller can deploy the
// policy. Cluster-wide policies are always allowed. A namespaced policy is
// allowed when all its rules target resources in the allow list. When the
// policy is not allowed, the second return value lists the targets that
// are not allowed.
func isNamespacedPolicyAllowed(policy policiesv1.Policy, allowed namespacedPoliciesAllowedResources) (bool, []string) {
	if policy.GetNamespace() == "" {
		return true, nil
	}

	disallowed := allowed.disallowedTargets(policy.GetRules())
	return len(disallowed) == 0, disallowed
}

// namespacedPolicyRejectedMessage builds the message of the PolicyActive
// condition for a rejected namespaced policy.
func namespacedPolicyRejectedMessage(disallowed []string, allowed namespacedPoliciesAllowedResources, configMapName string) string {
	var message strings.Builder

	message.WriteString("The policy is not deployed. ")
	if len(allowed) == 0 {
		message.WriteString("The allow list of resources for namespaced policies is empty. ")
		fmt.Fprintf(&message, "The controller reads the allow list from the key %s of the file %s in the ConfigMap %s. ",
			constants.ControllerConfigNamespacedPoliciesAllowedResourcesKey, constants.ControllerConfigKey, configMapName)
	} else {
		message.WriteString("The cluster administrator does not allow namespaced policies to target these resources (resource.apiGroup): ")
		message.WriteString(strings.Join(disallowed, ", "))
		message.WriteString(". ")
	}

	if slices.ContainsFunc(disallowed, func(target string) bool { return strings.Contains(target, wildcard) }) {
		message.WriteString("Namespaced policies cannot use wildcards in apiGroups or resources. Replace each wildcard with a resource name. ")
	}

	message.WriteString("To deploy this policy, ask the cluster administrator to add the resources that the policy targets to the Helm value namespacedPoliciesAllowedResources.")

	return message.String()
}

// controllerConfigMapPredicate returns a predicate that matches only the
// controller configuration ConfigMap.
func controllerConfigMapPredicate(namespace, name string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetName() == name && object.GetNamespace() == namespace
	})
}

// findAllPolicyServers maps a change of the controller configuration
// ConfigMap to a reconcile request for every PolicyServer in the cluster.
func findAllPolicyServers(ctx context.Context, k8sClient client.Client, log logr.Logger) []reconcile.Request {
	policyServers := policiesv1.PolicyServerList{}
	if err := k8sClient.List(ctx, &policyServers); err != nil {
		log.Error(err, "cannot list PolicyServers after a change of the controller configuration")
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(policyServers.Items))
	for _, policyServer := range policyServers.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: policyServer.Name},
		})
	}
	return requests
}
