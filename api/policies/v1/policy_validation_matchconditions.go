package v1

/*
The following code is taken from the Kubernetes source code
at pkg/apis/admissionregistration/validation/validation.go
*/

/*
Copyright 2017 The Kubernetes Authors.

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

import (
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

type validationOptions struct {
	ignoreMatchConditions                   bool
	allowParamsInMatchConditions            bool
	requireNoSideEffects                    bool
	requireRecognizedAdmissionReviewVersion bool
	requireUniqueWebhookNames               bool
	allowInvalidLabelValueInSelector        bool
	preexistingExpressions                  preexistingExpressions
	strictCostEnforcement                   bool
}

type preexistingExpressions struct {
	matchConditionExpressions sets.Set[string]
}

func validateMatchConditions(m []admissionregistrationv1.MatchCondition, opts validationOptions, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	conditionNames := sets.NewString()
	if len(m) > 64 {
		allErrors = append(allErrors, field.TooMany(fldPath, len(m), 64))
	}
	for i, matchCondition := range m {
		allErrors = append(allErrors, validateMatchCondition(&matchCondition, opts, fldPath.Index(i))...)
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

func validateMatchCondition(v *admissionregistrationv1.MatchCondition, opts validationOptions, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	trimmedExpression := strings.TrimSpace(v.Expression)
	if len(trimmedExpression) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("expression"), ""))
	} else {
		allErrors = append(allErrors, validateMatchConditionsExpression(trimmedExpression, opts, fldPath.Child("expression"))...)
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

func validateCELCondition(compiler plugincel.Compiler, expression plugincel.ExpressionAccessor, variables plugincel.OptionalVariableDeclarations, envType environment.Type, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	result := compiler.CompileCELExpression(expression, variables, envType)
	if result.Error != nil {
		allErrors = append(allErrors, convertCELErrorToValidationError(fldPath, expression, result.Error))
	}
	return allErrors
}

func convertCELErrorToValidationError(fldPath *field.Path, expression plugincel.ExpressionAccessor, err error) *field.Error {
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

func validateMatchConditionsExpression(expression string, opts validationOptions, fldPath *field.Path) field.ErrorList {
	envType := environment.NewExpressions
	if opts.preexistingExpressions.matchConditionExpressions.Has(expression) {
		envType = environment.StoredExpressions
	}
	var compiler plugincel.Compiler
	if opts.strictCostEnforcement {
		compiler = strictStatelessCELCompiler
	} else {
		compiler = nonStrictStatelessCELCompiler
	}
	return validateCELCondition(compiler, &matchconditions.MatchCondition{
		Expression: expression,
	}, plugincel.OptionalVariableDeclarations{
		HasParams:     opts.allowParamsInMatchConditions,
		HasAuthorizer: true,
		StrictCost:    opts.strictCostEnforcement,
	}, envType, fldPath)
}

// statelessCELCompiler does not support variable composition (and thus is stateless). It should be used when
// variable composition is not allowed, for example, when validating MatchConditions.
// strictStatelessCELCompiler is a cel Compiler that enforces strict cost enforcement.
// nonStrictStatelessCELCompiler is a cel Compiler that does not enforce strict cost enforcement.
var (
	strictStatelessCELCompiler    = plugincel.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true))
	nonStrictStatelessCELCompiler = plugincel.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), false))
)
