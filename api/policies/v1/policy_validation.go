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
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

// nonStrictStatelessCELCompiler is a cel Compiler that does not enforce strict cost enforcement.
//
//nolint:gochecknoglobals // lets keep the compiler available for the how module
var (
	nonStrictStatelessCELCompiler = plugincel.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), false))
)

const maxMatchConditionsCount = 64

func validatePolicyCreate(policy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validateRulesField(policy)...)
	allErrors = append(allErrors, validateMatchConditions(policy.GetMatchConditions(), field.NewPath("spec").Child("matchConditions"))...)
	return allErrors
}

func validatePolicyUpdate(oldPolicy, newPolicy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validateRulesField(newPolicy)...)
	allErrors = append(allErrors, validateMatchConditions(newPolicy.GetMatchConditions(), field.NewPath("spec").Child("matchConditions"))...)
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

func validatePolicyServerField(oldPolicy, newPolicy Policy) *field.Error {
	if oldPolicy.GetPolicyServer() != newPolicy.GetPolicyServer() {
		return field.Forbidden(field.NewPath("spec").Child("policyServer"), "the field is immutable")
	}

	return nil
}

func validatePolicyModeField(oldPolicy, newPolicy Policy) *field.Error {
	if oldPolicy.GetPolicyMode() == "protect" && newPolicy.GetPolicyMode() == "monitor" {
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

func validateMatchConditions(m []admissionregistrationv1.MatchCondition, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	conditionNames := sets.NewString()
	if len(m) > maxMatchConditionsCount {
		allErrors = append(allErrors, field.TooMany(fldPath, len(m), maxMatchConditionsCount))
	}
	for i, matchCondition := range m {
		allErrors = append(allErrors, validateMatchCondition(&matchCondition, fldPath.Index(i))...)
		if len(matchCondition.Name) > 0 {
			if conditionNames.Has(matchCondition.Name) {
				allErrors = append(allErrors, field.Duplicate(fldPath.Index(i).Child("name"), matchCondition.Name))
			} else {
				conditionNames.Insert(matchCondition.Name)
			}
		}
	}
	return allErrors
}

func validateMatchCondition(v *admissionregistrationv1.MatchCondition, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	trimmedExpression := strings.TrimSpace(v.Expression)
	if len(trimmedExpression) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("expression"), ""))
	} else {
		allErrors = append(allErrors, validateMatchConditionsExpression(trimmedExpression, fldPath.Child("expression"))...)
	}
	if len(v.Name) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("name"), ""))
	} else {
		for _, msg := range validation.IsQualifiedName(v.Name) {
			allErrors = append(allErrors, field.Invalid(fldPath, v.Name, msg))
		}
	}
	return allErrors
}

func convertCELErrorToValidationError(fldPath *field.Path, expression plugincel.ExpressionAccessor, err error) *field.Error {
	//nolint:errorlint // The code is not only checking the type. It is also using the errors fields.
	if celErr, ok := err.(*cel.Error); ok {
		switch celErr.Type {
		case cel.ErrorTypeRequired:
			return field.Required(fldPath, celErr.Detail)
		case cel.ErrorTypeInvalid:
			return field.Invalid(fldPath, expression.GetExpression(), celErr.Detail)
		case cel.ErrorTypeInternal:
			return field.InternalError(fldPath, celErr)
		}
	}
	return field.InternalError(fldPath, fmt.Errorf("unsupported error type: %w", err))
}

func validateMatchConditionsExpression(expressionStr string, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	expression := &matchconditions.MatchCondition{
		Expression: expressionStr,
	}
	result := nonStrictStatelessCELCompiler.CompileCELExpression(expression, plugincel.OptionalVariableDeclarations{
		HasParams:     false,
		HasAuthorizer: true,
		StrictCost:    false,
	}, environment.NewExpressions)
	if result.Error != nil {
		allErrors = append(allErrors, convertCELErrorToValidationError(fldPath, expression, result.Error))
	}
	return allErrors
}
