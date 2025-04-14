package controller

import "fmt"

// Error to be returned when a controller detect a change in a immutable field
type ImmutableFieldChangeError struct{}

func (e ImmutableFieldChangeError) Error() string {
	return fmt.Sprintf("immutable field changed")
}
