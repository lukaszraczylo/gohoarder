package scanerr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
)

func TestIsInfrastructure(t *testing.T) {
	tests := []struct {
		err  error
		name string
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "deadline", err: fmt.Errorf("scan: %w", context.DeadlineExceeded), want: true},
		{name: "canceled", err: fmt.Errorf("scan: %w", context.Canceled), want: true},
		{name: "net error", err: &url.Error{Op: "Post", URL: "http://x", Err: &net.OpError{Op: "dial", Err: errors.New("refused")}}, want: true},
		{name: "upstream 503", err: fmt.Errorf("wrapped: %w", &StatusError{Service: "OSV API", Code: 503}), want: true},
		{name: "upstream 429", err: &StatusError{Service: "OSV API", Code: 429}, want: true},
		{name: "upstream 404", err: &StatusError{Service: "OSV API", Code: 404}, want: false},
		{name: "marked", err: fmt.Errorf("trivy: %w", ErrInfrastructure), want: true},
		{name: "plain", err: errors.New("scanner exploded"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsInfrastructure(tt.err); got != tt.want {
				t.Errorf("IsInfrastructure(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestStatusErrorMessage(t *testing.T) {
	err := &StatusError{Service: "OSV API", Code: 500, Body: "boom"}
	if got, want := err.Error(), "OSV API returned status 500: boom"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
