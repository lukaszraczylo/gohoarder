package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ErrorsTestSuite struct {
	suite.Suite
}

func TestErrorsTestSuite(t *testing.T) {
	suite.Run(t, new(ErrorsTestSuite))
}

func (s *ErrorsTestSuite) TestNew() {
	tests := []struct {
		name    string
		code    string
		message string
	}{
		{
			name:    "simple_error",
			code:    ErrCodeNotFound,
			message: "Resource not found",
		},
		{
			name:    "empty_message",
			code:    ErrCodeBadRequest,
			message: "",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			err := New(tt.code, tt.message)
			s.Equal(tt.code, err.Code)
			s.Equal(tt.message, err.Message)
			s.Nil(err.Details)
			s.Nil(err.Trace)
			s.Nil(err.Cause)
		})
	}
}

func (s *ErrorsTestSuite) TestNewf() {
	tests := []struct {
		name     string
		code     string
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "formatted_message",
			code:     ErrCodePackageNotFound,
			format:   "Package %s@%s not found",
			args:     []interface{}{"react", "18.2.0"},
			expected: "Package react@18.2.0 not found",
		},
		{
			name:     "no_args",
			code:     ErrCodeInternalServer,
			format:   "Internal error",
			args:     []interface{}{},
			expected: "Internal error",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			err := Newf(tt.code, tt.format, tt.args...)
			s.Equal(tt.code, err.Code)
			s.Equal(tt.expected, err.Message)
		})
	}
}

func (s *ErrorsTestSuite) TestWithDetails() {
	tests := []struct {
		name    string
		details interface{}
	}{
		{
			name:    "map_details",
			details: map[string]string{"key": "value"},
		},
		{
			name:    "string_details",
			details: "some details",
		},
		{
			name:    "nil_details",
			details: nil,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			err := New(ErrCodeBadRequest, "test").WithDetails(tt.details)
			s.Equal(tt.details, err.Details)
		})
	}
}

func (s *ErrorsTestSuite) TestWithTrace() {
	trace := []string{"file1.go:10", "file2.go:20"}
	err := New(ErrCodeInternalServer, "test").WithTrace(trace)
	s.Equal(trace, err.Trace)
}

func (s *ErrorsTestSuite) TestWithCause() {
	cause := errors.New("underlying error")
	err := New(ErrCodeStorageFailure, "test").WithCause(cause)
	s.Equal(cause, err.Cause)
	s.Contains(err.Error(), "underlying error")
}

func (s *ErrorsTestSuite) TestWrap() {
	cause := errors.New("original error")
	wrapped := Wrap(cause, ErrCodeDatabaseFailure, "database connection failed")

	s.Equal(ErrCodeDatabaseFailure, wrapped.Code)
	s.Equal("database connection failed", wrapped.Message)
	s.Equal(cause, wrapped.Cause)
	s.True(errors.Is(wrapped, cause))
}

func (s *ErrorsTestSuite) TestWrapf() {
	cause := errors.New("connection refused")
	wrapped := Wrapf(cause, ErrCodeUpstreamFailure, "failed to connect to %s", "registry.npmjs.org")

	s.Equal(ErrCodeUpstreamFailure, wrapped.Code)
	s.Equal("failed to connect to registry.npmjs.org", wrapped.Message)
	s.Equal(cause, wrapped.Cause)
}

func (s *ErrorsTestSuite) TestErrorString() {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "error_without_cause",
			err:      New(ErrCodeNotFound, "not found"),
			expected: "NOT_FOUND: not found",
		},
		{
			name:     "error_with_cause",
			err:      Wrap(errors.New("io error"), ErrCodeStorageFailure, "storage failed"),
			expected: "STORAGE_FAILURE: storage failed (caused by: io error)",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			s.Equal(tt.expected, tt.err.Error())
		})
	}
}

func (s *ErrorsTestSuite) TestCommonConstructors() {
	tests := []struct {
		name     string
		fn       func() *Error
		wantCode string
	}{
		{
			name:     "bad_request",
			fn:       func() *Error { return BadRequest("invalid input") },
			wantCode: ErrCodeBadRequest,
		},
		{
			name:     "unauthorized",
			fn:       func() *Error { return Unauthorized("invalid token") },
			wantCode: ErrCodeUnauthorized,
		},
		{
			name:     "forbidden",
			fn:       func() *Error { return Forbidden("access denied") },
			wantCode: ErrCodeForbidden,
		},
		{
			name:     "not_found",
			fn:       func() *Error { return NotFound("resource missing") },
			wantCode: ErrCodeNotFound,
		},
		{
			name:     "internal_server",
			fn:       func() *Error { return InternalServer("server error") },
			wantCode: ErrCodeInternalServer,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			err := tt.fn()
			s.Equal(tt.wantCode, err.Code)
		})
	}
}

func (s *ErrorsTestSuite) TestPackageNotFound() {
	err := PackageNotFound("lodash", "4.17.21")
	s.Equal(ErrCodePackageNotFound, err.Code)
	s.Equal("Package lodash@4.17.21 not found", err.Message)
	s.NotNil(err.Details)

	details, ok := err.Details.(map[string]string)
	s.True(ok)
	s.Equal("lodash", details["package"])
	s.Equal("4.17.21", details["version"])
}

func (s *ErrorsTestSuite) TestQuotaExceeded() {
	limit := int64(1000000)
	err := QuotaExceeded(limit)
	s.Equal(ErrCodeQuotaExceeded, err.Code)
	s.NotNil(err.Details)

	details, ok := err.Details.(map[string]interface{})
	s.True(ok)
	s.Equal(limit, details["limit_bytes"])
}

func (s *ErrorsTestSuite) TestUnwrap() {
	cause := errors.New("root cause")
	wrapped := Wrap(cause, ErrCodeDatabaseFailure, "db error")

	unwrapped := wrapped.Unwrap()
	s.Equal(cause, unwrapped)
}

// Benchmark tests
func BenchmarkNewError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrCodeNotFound, "test error")
	}
}

func BenchmarkNewErrorWithDetails(b *testing.B) {
	details := map[string]string{"key": "value"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = New(ErrCodeNotFound, "test error").WithDetails(details)
	}
}

// Test edge cases
func (s *ErrorsTestSuite) TestEdgeCases() {
	s.Run("nil_error_wrap", func() {
		wrapped := Wrap(nil, ErrCodeInternalServer, "test")
		s.Nil(wrapped.Cause)
	})

	s.Run("chained_wrapping", func() {
		err1 := errors.New("base")
		err2 := Wrap(err1, ErrCodeStorageFailure, "storage")
		err3 := Wrap(err2, ErrCodeInternalServer, "internal")

		s.True(errors.Is(err3, err2))
		s.True(errors.Is(err3, err1))
	})

	s.Run("large_details", func() {
		largeDetails := make(map[string]string)
		for i := 0; i < 1000; i++ {
			largeDetails[string(rune(i))] = "value"
		}
		err := New(ErrCodeBadRequest, "test").WithDetails(largeDetails)
		s.Equal(largeDetails, err.Details)
	})
}

// Table-driven test for error codes
func TestGetHTTPStatus(t *testing.T) {
	tests := []struct {
		code           string
		expectedStatus int
	}{
		{ErrCodeBadRequest, 400},
		{ErrCodeUnauthorized, 401},
		{ErrCodeForbidden, 403},
		{ErrCodeNotFound, 404},
		{ErrCodeConflict, 409},
		{ErrCodePayloadTooLarge, 413},
		{ErrCodeChecksumMismatch, 422},
		{ErrCodeRateLimited, 429},
		{ErrCodeInternalServer, 500},
		{ErrCodeDatabaseFailure, 500},
		{ErrCodeUpstreamFailure, 502},
		{ErrCodeServiceUnavailable, 503},
		{"UNKNOWN_CODE", 500}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			assert.Equal(t, tt.expectedStatus, GetHTTPStatus(tt.code))
		})
	}
}
