package errors

import (
	"fmt"
)

// Error represents a structured error with code and details
type Error struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
	Trace   []string    `json:"trace,omitempty"`
	Cause   error       `json:"-"` // Internal cause, not serialized
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

// Newf creates a new error with formatted message
func Newf(code, format string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// WithDetails adds details to the error
func (e *Error) WithDetails(details interface{}) *Error {
	e.Details = details
	return e
}

// WithTrace adds stack trace to the error
func (e *Error) WithTrace(trace []string) *Error {
	e.Trace = trace
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

// Wrapf wraps an existing error with formatted message
func Wrapf(err error, code, format string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   err,
	}
}

// Common error constructors
func BadRequest(message string) *Error {
	return New(ErrCodeBadRequest, message)
}

func Unauthorized(message string) *Error {
	return New(ErrCodeUnauthorized, message)
}

func Forbidden(message string) *Error {
	return New(ErrCodeForbidden, message)
}

func NotFound(message string) *Error {
	return New(ErrCodeNotFound, message)
}

func InternalServer(message string) *Error {
	return New(ErrCodeInternalServer, message)
}

func PackageNotFound(name, version string) *Error {
	return New(ErrCodePackageNotFound, fmt.Sprintf("Package %s@%s not found", name, version)).
		WithDetails(map[string]string{
			"package": name,
			"version": version,
		})
}

func QuotaExceeded(limit int64) *Error {
	return New(ErrCodeQuotaExceeded, "Storage quota exceeded").
		WithDetails(map[string]interface{}{
			"limit_bytes": limit,
		})
}
