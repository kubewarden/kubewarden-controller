package v1

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/stdlib"
	"github.com/google/cel-go/common/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func validatePolicyGroupCreate(policy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validatePolicyCreate(policy)...)
	if err := validatePolicyGroupMembers(policy); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validatePolicyGroupExpressionField(policy); err != nil {
		allErrors = append(allErrors, err)
	}

	return allErrors
}

func validatePolicyGroupUpdate(oldPolicy, newPolicy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validatePolicyUpdate(oldPolicy, newPolicy)...)
	if err := validatePolicyGroupMembers(newPolicy); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validatePolicyGroupExpressionField(newPolicy); err != nil {
		allErrors = append(allErrors, err)
	}

	return allErrors
}

// validatePolicyGroupMembers validates that a policy group has at least one policy member.
func validatePolicyGroupMembers(policy Policy) *field.Error {
	if len(policy.GetPolicyMembers()) == 0 {
		return field.Required(field.NewPath("spec").Child("policies"), "policy groups must have at least one policy member")
	}

	return nil
}

// validatePolicyGroupExpressionField validates that the expression is a valid CEL expression that evaluates to a boolean.
// Only the following operators are allowed: equals, not equals, logical or, logical and, and logical not.
// Policy members are imported as custom functions that take no arguments and return a boolean.
func validatePolicyGroupExpressionField(policy Policy) *field.Error {
	expressionField := field.NewPath("spec").Child("expression")

	if policy.GetExpression() == "" {
		return field.Required(expressionField, "must be non-empty")
	}

	// Create a CEL environment with custom functions for each policy member
	var opts []cel.EnvOption
	for _, p := range policy.GetPolicyMembers() {
		fn := cel.Function(p.Name, cel.Overload(p.Name, []*cel.Type{}, types.BoolType))
		opts = append(opts, fn)
	}

	// Import only equals, not equals, logical or, logical and, and logical not operators
	// from the standard library
	allowedOperators := map[string]bool{
		operators.Equals:     true,
		operators.NotEquals:  true,
		operators.LogicalOr:  true,
		operators.LogicalAnd: true,
		operators.LogicalNot: true,
	}
	for _, fn := range stdlib.Functions() {
		if !allowedOperators[fn.Name()] {
			continue
		}

		opts = append(opts, cel.Function(fn.Name(),
			func(*decls.FunctionDecl) (*decls.FunctionDecl, error) {
				return fn, nil
			}))
	}

	env, err := cel.NewCustomEnv(
		opts...,
	)
	if err != nil {
		return field.InternalError(expressionField, fmt.Errorf("error creating CEL environment: %w", err))
	}

	ast, issues := env.Compile(policy.GetExpression())
	if issues != nil && issues.Err() != nil {
		return field.Invalid(expressionField, policy.GetExpression(), fmt.Sprintf("compilation failed: %v", issues.Err()))
	}
	if ast.OutputType() != types.BoolType {
		return field.Invalid(expressionField, policy.GetExpression(), "must evaluate to bool")
	}

	return nil
}
