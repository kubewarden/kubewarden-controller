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

func validatePolicyCreate(policy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validateRulesField(policy)...)
	allErrors = append(allErrors, validateMatchConditionsField(policy)...)

	return allErrors
}

func validatePolicyUpdate(oldPolicy, newPolicy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validateRulesField(newPolicy)...)
	allErrors = append(allErrors, validateMatchConditionsField(newPolicy)...)
	if err := validatePolicyServerField(oldPolicy, newPolicy); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validatePolicyModeField(oldPolicy, newPolicy); err != nil {
		allErrors = append(allErrors, err)
	}

	return allErrors
}

// Validates the spec.Rules field for non-empty, webhook-valid rules.
func validateRulesField(policy Policy) field.ErrorList {
	var allErrors field.ErrorList
	rulesField := field.NewPath("spec", "rules")

	if len(policy.GetRules()) == 0 {
		allErrors = append(allErrors, field.Required(rulesField, "a value must be specified"))

		return allErrors
	}

	for _, rule := range policy.GetRules() {
		switch {
		case len(rule.Operations) == 0:
			opField := rulesField.Child("operations")
			allErrors = append(allErrors, field.Required(opField, "a value must be specified"))
		case len(rule.Rule.APIVersions) == 0 || len(rule.Rule.Resources) == 0:
			allErrors = append(allErrors, field.Required(rulesField, "apiVersions and resources must have specified values"))
		default:
			allErrors = append(allErrors, checkOperationsArrayForEmptyString(rule.Operations, rulesField)...)
			allErrors = append(allErrors, checkRulesArrayForEmptyString(rule.Rule.APIVersions, rulesField.Child("rule.apiVersions"))...)
			allErrors = append(allErrors, checkRulesArrayForEmptyString(rule.Rule.Resources, rulesField.Child("rule.resources"))...)
		}
	}

	return allErrors
}

// checkOperationsArrayForEmptyString checks if any of the values in the operations array is the empty string and returns
// an error if this is true.
func checkOperationsArrayForEmptyString(operationsArray []admissionregistrationv1.OperationType, rulesField *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	for i, operation := range operationsArray {
		if operation == "" {
			allErrors = append(allErrors, field.Required(rulesField.Child("operations").Index(i), "must be non-empty"))
		}
	}

	return allErrors
}

// checkRulesArrayForEmptyString checks if any of the values specified is the empty string and returns an error if this
// is true.
func checkRulesArrayForEmptyString(rulesArray []string, rulesField *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	for i, apiVersion := range rulesArray {
		if apiVersion == "" {
			allErrors = append(allErrors, field.Required(rulesField.Index(i), "must be non-empty"))
		}
	}

	return allErrors
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

	return validateMatchConditions(policy.GetMatchConditions(), opts, field.NewPath("spec").Child("matchConditions"))
}

func validatePolicyServerField(oldPolicy, newPolicy Policy) *field.Error {
	if oldPolicy.GetPolicyServer() != newPolicy.GetPolicyServer() {
		return field.Forbidden(field.NewPath("spec").Child("policyServer"), "the field is immutable")
	}

	return nil
}

func validatePolicyModeField(oldPolicy, newPolicy Policy) *field.Error {
	if oldPolicy.GetPolicyMode() != newPolicy.GetPolicyMode() {
		return field.Forbidden(field.NewPath("spec").Child("mode"), "field cannot transition from protect to monitor. Recreate instead.")
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
