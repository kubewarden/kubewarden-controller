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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"k8s.io/apimachinery/pkg/util/validation/field"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Validates the spec.Rules field for non-empty, webhook-valid rules.
func validateRulesField(policy Policy) field.ErrorList {
	errs := field.ErrorList{}
	rulesField := field.NewPath("spec", "rules")

	if len(policy.GetRules()) == 0 {
		errs = append(errs, field.Required(rulesField, "a value must be specified"))

		return errs
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
		return errs
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

			return field.Invalid(apiVersionField, "", fieldName+" value cannot contain the empty string")
		}
	}

	return nil
}

func validateMatchConditionsField(policy Policy) field.ErrorList {
	// taken from the configuration for validating MutatingWebhookConfiguration:
	// https://github.com/kubernetes/kubernetes/blob/c052f64689ee26aace4689f2433c5c7dcf1931ad/pkg/apis/admissionregistration/validation/validation.go#L257
	opts := validationOptions{
		ignoreMatchConditions:                   false,
		allowParamsInMatchConditions:            false,
		requireNoSideEffects:                    true,
		requireRecognizedAdmissionReviewVersion: true,
		requireUniqueWebhookNames:               true,
		allowInvalidLabelValueInSelector:        false,
		// strictCostEnforcement enables cost enforcement for CEL.
		//	 This is enabled with the StrictCostEnforcementForWebhooks feature gate
		//	 (alpha on v1.30). Don't check it for now. Nevertheless, will get
		//	 checked by the k8s API on WebhookConfiguration creation if the feature
		//   gate is enabled.
		strictCostEnforcement: false,
	}

	if errs := validateMatchConditions(policy.GetMatchConditions(), opts, field.NewPath("spec").Child("matchConditions")); len(errs) != 0 {
		return errs
	}
	return nil
}

func validatePolicyGroupMembers(policy Policy) *field.Error {
	if policy.IsPolicyGroup() && len(policy.GetPolicyMembers()) == 0 {
		return field.Invalid(field.NewPath("spec").Child("policies"), "", "policy groups must have at least one policy member")
	}
	return nil
}

// prepareInvalidAPIError is a shorthand for generating an invalid apierrors.StatusError with data from a policy.
func prepareInvalidAPIError(policy Policy, errorList field.ErrorList) *apierrors.StatusError {
	return apierrors.NewInvalid(
		policy.GetObjectKind().GroupVersionKind().GroupKind(),
		policy.GetName(),
		errorList,
	)
}

func validatePolicyUpdate(oldPolicy, newPolicy Policy) error {
	errList := field.ErrorList{}

	if errs := validateRulesField(newPolicy); len(errs) != 0 {
		errList = append(errList, errs...)
	}

	if errs := validateMatchConditionsField(newPolicy); len(errs) != 0 {
		errList = append(errList, errs...)
	}

	if newPolicy.GetPolicyServer() != oldPolicy.GetPolicyServer() {
		var errs field.ErrorList
		p := field.NewPath("spec")
		pp := p.Child("policyServer")
		errs = append(errs, field.Forbidden(pp, "the field is immutable"))
		errList = append(errList, errs...)
	}

	if newPolicy.GetPolicyMode() == "monitor" && oldPolicy.GetPolicyMode() == "protect" {
		var errs field.ErrorList
		p := field.NewPath("spec")
		pp := p.Child("mode")
		errs = append(errs, field.Forbidden(pp, "field cannot transition from protect to monitor. Recreate instead."))
		errList = append(errList, errs...)
	}

	if err := validatePolicyGroupMembers(newPolicy); err != nil {
		errList = append(errList, err)
	}

	if len(errList) != 0 {
		return prepareInvalidAPIError(newPolicy, errList)
	}
	return nil
}
