// Package scanerr classifies scanner failures so callers can tell an
// unavailable scanner from a scan that found the package unsafe.
package scanerr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ErrInfrastructure marks a failure of the scanning machinery (timeout,
// unreachable service) as opposed to a verdict on the package.
var ErrInfrastructure = errors.New("scanner infrastructure failure")

// StatusError is an HTTP status returned by a scanner's backing service.
type StatusError struct {
	Service string
	Body    string
	Code    int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s returned status %d: %s", e.Service, e.Code, e.Body)
}

// IsInfrastructure reports whether err means the scanner could not run
// (timeout, network failure, upstream 5xx or rate limit).
func IsInfrastructure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrInfrastructure) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Code >= http.StatusInternalServerError || statusErr.Code == http.StatusTooManyRequests
	}
	return false
}

// DetailInfrastructure is the scan-result detail key that marks an error result as infrastructure.
const DetailInfrastructure = "infrastructure_error"

// ErrorDetails builds the Details of a scan-error result.
func ErrorDetails(reason string, infra bool) map[string]interface{} {
	return map[string]interface{}{"error": reason, DetailInfrastructure: infra}
}

var networkMarkers = []string{"ENOTFOUND", "ETIMEDOUT", "ECONNREFUSED", "ECONNRESET", "EAI_AGAIN", "i/o timeout", "no such host", "connection refused"}

// NetworkFailure reports whether a tool's output shows it could not reach the network.
func NetworkFailure(output string) bool {
	for _, m := range networkMarkers {
		if strings.Contains(output, m) {
			return true
		}
	}
	return false
}
