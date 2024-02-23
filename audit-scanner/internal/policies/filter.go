package policies

import (
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog/log"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// returns all policies that should be audited. For a policy to be auditable it must have background-audit enabled,
// be active, contain the CREATE operation and not select all resources with '*'
func filterAuditablePolicies(policies []policiesv1.Policy) []policiesv1.Policy {
	filteredPolicies := []policiesv1.Policy{}

	for _, policy := range policies {
		if policy.GetBackgroundAudit() &&
			policy.GetStatus().PolicyStatus == policiesv1.PolicyStatusActive &&
			isCreateActionPresentWithoutAllResources(policy) {
			filteredPolicies = append(filteredPolicies, policy)
		} else {
			log.Debug().Str("policy", policy.GetUniqueName()).
				Bool("backgroundAudit", policy.GetBackgroundAudit()).
				Bool("active", policy.GetStatus().PolicyStatus == policiesv1.PolicyStatusActive).
				Bool("create", isCreateActionPresentWithoutAllResources(policy)).
				Msg("not auditable policy, skipping!")
		}
	}

	return filteredPolicies
}

func isCreateActionPresentWithoutAllResources(policy policiesv1.Policy) bool {
	for _, rule := range policy.GetRules() {
		for _, operation := range rule.Operations {
			if operation == admissionregistrationv1.Create &&
				!contains(rule.Resources, "*") &&
				!contains(rule.APIGroups, "*") &&
				!contains(rule.APIVersions, "*") {
				return true
			}
		}
	}

	return false
}

func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
