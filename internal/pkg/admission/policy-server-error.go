package admission

import (
	"errors"
)

// PolicyServerNotReadyError error is raised when the PolicyServer
// deployment is not yet ready
type PolicyServerNotReadyError struct {
	Message string
}

// Error returns a human description of the error
func (e *PolicyServerNotReadyError) Error() string {
	return e.Message
}

// PolicyServerNotReady returns true if the error is a NoVersionFoundError instance
func (e *PolicyServerNotReadyError) PolicyServerNotReady() bool {
	return true
}

// IsPolicyServerNotReady returns true when the given error is of type
// PolicyServerNotReadyError
func IsPolicyServerNotReady(err error) bool {
	var e *PolicyServerNotReadyError
	if errors.As(err, &e) {
		return e.PolicyServerNotReady()
	}

	return false
}
