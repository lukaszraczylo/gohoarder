package errors

import (
	"net/http"
	"time"

	json "github.com/goccy/go-json"
)

// Response is the standard API response envelope
type Response struct {
	Success  bool           `json:"success"`
	Data     interface{}    `json:"data,omitempty"`
	Error    *ErrorResponse `json:"error,omitempty"`
	Metadata *ResponseMeta  `json:"metadata,omitempty"`
}

// ErrorResponse contains error details
type ErrorResponse struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
	Trace   []string    `json:"trace,omitempty"`
}

// ResponseMeta contains request metadata
type ResponseMeta struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
	Duration  string `json:"duration,omitempty"`
	Version   string `json:"version"`
}

// WriteJSON writes a success response as JSON
func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}, meta *ResponseMeta) {
	response := Response{
		Success:  statusCode < 400,
		Data:     data,
		Metadata: meta,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Fallback to simple error response
		http.Error(w, `{"success":false,"error":{"code":"ENCODING_ERROR","message":"Failed to encode response"}}`, http.StatusInternalServerError)
	}
}

// WriteError writes an error response as JSON
func WriteError(w http.ResponseWriter, statusCode int, err *Error, meta *ResponseMeta) {
	errResp := &ErrorResponse{
		Code:    err.Code,
		Message: err.Message,
		Details: err.Details,
		Trace:   err.Trace,
	}

	response := Response{
		Success:  false,
		Error:    errResp,
		Metadata: meta,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if encErr := json.NewEncoder(w).Encode(response); encErr != nil {
		// Fallback to simple error response
		http.Error(w, `{"success":false,"error":{"code":"ENCODING_ERROR","message":"Failed to encode error response"}}`, http.StatusInternalServerError)
	}
}

// WriteErrorSimple writes an error without metadata
func WriteErrorSimple(w http.ResponseWriter, err *Error) {
	statusCode := GetHTTPStatus(err.Code)
	meta := &ResponseMeta{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	WriteError(w, statusCode, err, meta)
}

// WriteJSONSimple writes a success response without metadata
func WriteJSONSimple(w http.ResponseWriter, statusCode int, data interface{}) {
	meta := &ResponseMeta{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	WriteJSON(w, statusCode, data, meta)
}
