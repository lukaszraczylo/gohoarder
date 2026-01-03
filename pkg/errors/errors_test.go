package errors

import (
	"errors"
	"testing"

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

func (s *ErrorsTestSuite) TestWithDetails() {
	tests := []struct {
		details interface{}
		name    string
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
