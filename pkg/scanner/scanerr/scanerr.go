// Package scanerr classifies scanner failures so callers can tell an
// unavailable scanner from a scan that found the package unsafe.
package scanerr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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
