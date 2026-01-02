package errors

// Error codes following consistent naming convention
const (
	// Client errors (4xx)
	ErrCodeBadRequest      = "BAD_REQUEST"
	ErrCodeUnauthorized    = "UNAUTHORIZED"
	ErrCodeForbidden       = "FORBIDDEN"
	ErrCodeNotFound        = "NOT_FOUND"
	ErrCodeRateLimited     = "RATE_LIMITED"
	ErrCodePayloadTooLarge = "PAYLOAD_TOO_LARGE"
	ErrCodeInvalidAPIKey   = "INVALID_API_KEY" // #nosec G101 -- Not a credential, just an error code constant
	ErrCodeQuotaExceeded   = "QUOTA_EXCEEDED"
	ErrCodeConflict        = "CONFLICT"
	ErrCodeInvalidConfig   = "INVALID_CONFIG"

	// Package-specific errors
	ErrCodePackageNotFound   = "PACKAGE_NOT_FOUND"
	ErrCodeVersionNotFound   = "VERSION_NOT_FOUND"
	ErrCodeChecksumMismatch  = "CHECKSUM_MISMATCH"
	ErrCodeCorruptPackage    = "CORRUPT_PACKAGE"
	ErrCodeSecurityBlocked   = "SECURITY_BLOCKED"
	ErrCodeSecurityViolation = "SECURITY_VIOLATION" // Package has vulnerabilities exceeding thresholds
	ErrCodeUpstreamError     = "UPSTREAM_ERROR"

	// Server errors (5xx)
	ErrCodeInternalServer     = "INTERNAL_SERVER_ERROR"
	ErrCodeStorageFailure     = "STORAGE_FAILURE"
	ErrCodeUpstreamFailure    = "UPSTREAM_FAILURE"
	ErrCodeDatabaseFailure    = "DATABASE_FAILURE"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	ErrCodeCircuitOpen        = "CIRCUIT_OPEN"
)

// HTTPStatusCode maps error codes to HTTP status codes
var HTTPStatusCode = map[string]int{
	ErrCodeBadRequest:         400,
	ErrCodeUnauthorized:       401,
	ErrCodeForbidden:          403,
	ErrCodeNotFound:           404,
	ErrCodeConflict:           409,
	ErrCodeRateLimited:        429,
	ErrCodePayloadTooLarge:    413,
	ErrCodeInvalidAPIKey:      401,
	ErrCodeQuotaExceeded:      429,
	ErrCodeInvalidConfig:      400,
	ErrCodePackageNotFound:    404,
	ErrCodeVersionNotFound:    404,
	ErrCodeChecksumMismatch:   422,
	ErrCodeCorruptPackage:     422,
	ErrCodeSecurityBlocked:    403,
	ErrCodeSecurityViolation:  426, // Upgrade Required
	ErrCodeUpstreamError:      502,
	ErrCodeInternalServer:     500,
	ErrCodeStorageFailure:     500,
	ErrCodeUpstreamFailure:    502,
	ErrCodeDatabaseFailure:    500,
	ErrCodeServiceUnavailable: 503,
	ErrCodeCircuitOpen:        503,
}

// GetHTTPStatus returns the HTTP status code for an error code
func GetHTTPStatus(code string) int {
	if status, ok := HTTPStatusCode[code]; ok {
		return status
	}
	return 500 // Default to internal server error
}
