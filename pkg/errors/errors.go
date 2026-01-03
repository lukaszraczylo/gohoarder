package errors

import (
	"fmt"
)

// Error represents a structured error with code and details
type Error struct {
	Details interface{} `json:"details,omitempty"`
	Cause   error       `json:"-"`
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Trace   []string    `json:"trace,omitempty"`
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the cause for errors.Is/As support
func (e *Error) Unwrap() error {
	return e.Cause
}

// New creates a new error with the given code and message
func New(code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// WithDetails adds details to the error
func (e *Error) WithDetails(details interface{}) *Error {
	e.Details = details
	return e
}

// WithCause adds an underlying cause to the error
func (e *Error) WithCause(cause error) *Error {
	e.Cause = cause
	return e
}

// Wrap wraps an existing error with a new code and message
func Wrap(err error, code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   err,
	}
}

// NotFound creates a not found error
func NotFound(message string) *Error {
	return New(ErrCodeNotFound, message)
}

// QuotaExceeded creates a quota exceeded error
func QuotaExceeded(limit int64) *Error {
	return New(ErrCodeQuotaExceeded, "Storage quota exceeded").
		WithDetails(map[string]interface{}{
			"limit_bytes": limit,
		})
}
