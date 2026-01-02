package common

import (
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// HandleUpstreamError logs an error and sends an HTTP 502 Bad Gateway response
// This is the common pattern used across all proxy handlers when upstream fetch fails
func HandleUpstreamError(w http.ResponseWriter, err error, url, context string) {
	log.Error().
		Err(err).
		Str("url", url).
		Str("context", context).
		Msg("Failed to fetch from upstream")

	http.Error(w, fmt.Sprintf("Failed to fetch %s", context), http.StatusBadGateway)
}

// CheckUpstreamStatus validates HTTP status code from upstream
// Returns error if status is not OK, closing body if needed
func CheckUpstreamStatus(statusCode int, body io.ReadCloser) error {
	if statusCode != http.StatusOK {
		if body != nil {
			body.Close() // #nosec G104 -- Cleanup, error not critical
		}
		return fmt.Errorf("upstream returned status %d", statusCode)
	}
	return nil
}

// HandleInvalidRequest sends a 400 Bad Request response for invalid proxy requests
func HandleInvalidRequest(w http.ResponseWriter, registry string) {
	http.Error(w, fmt.Sprintf("Invalid %s request", registry), http.StatusBadRequest)
}

// HandleInternalError logs an internal error and sends 500 response
func HandleInternalError(w http.ResponseWriter, err error, context string) {
	log.Error().
		Err(err).
		Str("context", context).
		Msg("Internal error processing request")

	http.Error(w, fmt.Sprintf("Internal error: %s", context), http.StatusInternalServerError)
}
