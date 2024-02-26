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

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Validates the spec.Rules field for non-empty, webhook-valid rules
func validateRulesField(policy Policy) error {
	errs := field.ErrorList{}
	rulesField := field.NewPath("spec", "rules")

	if len(policy.GetRules()) == 0 {
		errs = append(errs, field.Required(rulesField, "a value must be specified"))

		return prepareInvalidAPIError(policy, errs)
	}

	for _, rule := range policy.GetRules() {
		switch {
		case len(rule.Operations) == 0:
			opField := rulesField.Child("operations")
			errs = append(errs, field.Required(opField, "a value must be specified"))
		case len(rule.Rule.APIVersions) == 0 || len(rule.Rule.Resources) == 0:
			errs = append(errs, field.Required(rulesField, "apiVersions and resources must have specified values"))
		default:
			if err := checkOperationsArrayForEmptyString(rule.Operations, rulesField); err != nil {
				errs = append(errs, err)
			}

			if err := checkRulesArrayForEmptyString(rule.Rule.APIVersions, "rule.apiVersions", rulesField); err != nil {
				errs = append(errs, err)
			}

			if err := checkRulesArrayForEmptyString(rule.Rule.Resources, "rule.resources", rulesField); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) != 0 {
		return prepareInvalidAPIError(policy, errs)
	}

	return nil
}

// checkOperationsArrayForEmptyString checks if any of the values in the operations array is the empty string and returns
// an error if this is true.
func checkOperationsArrayForEmptyString(operationsArray []admissionregistrationv1.OperationType, rulesField *field.Path) *field.Error {
	for _, operation := range operationsArray {
		if operation == "" {
			return field.Invalid(rulesField.Child("operations"), "", "field value cannot contain the empty string")
		}
	}

	return nil
}

// checkRulesArrayForEmptyString checks if any of the values specified is the empty string and returns an error if this
// is true.
func checkRulesArrayForEmptyString(rulesArray []string, fieldName string, parentField *field.Path) *field.Error {
	for _, apiVersion := range rulesArray {
		if apiVersion == "" {
			apiVersionField := parentField.Child(fieldName)

			return field.Invalid(apiVersionField, "", fmt.Sprintf("%s value cannot contain the empty string", fieldName))
		}
	}

	return nil
}

// prepareInvalidAPIError is a shorthand for generating an invalid apierrors.StatusError with data from a policy
func prepareInvalidAPIError(policy Policy, errorList field.ErrorList) *apierrors.StatusError {
	return apierrors.NewInvalid(
		policy.GetObjectKind().GroupVersionKind().GroupKind(),
		policy.GetName(),
		errorList,
	)
}

func validatePolicyUpdate(oldPolicy, newPolicy Policy) error {
	if err := validateRulesField(newPolicy); err != nil {
		return err
	}

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
