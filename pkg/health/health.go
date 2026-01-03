package health

import (
	"context"
	"net/http"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/lukaszraczylo/gohoarder/internal/version"
)

// Status represents component health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// Check represents a single health check
type Check struct {
	Fn     func(context.Context) (Status, string) `json:"-"`
	Name   string                                 `json:"name"`
	Status Status                                 `json:"status"`
	Error  string                                 `json:"error,omitempty"`
}

// Response is the health check response
type Response struct {
	Data     *HealthData `json:"data,omitempty"`
	Metadata *Metadata   `json:"metadata,omitempty"`
	Success  bool        `json:"success"`
}

// HealthData contains health check data
type HealthData struct {
	Components map[string]*Component `json:"components"`
	Status     Status                `json:"status"`
	Version    string                `json:"version"`
	Uptime     string                `json:"uptime"`
}

// Component represents a system component
type Component struct {
	Status  Status                 `json:"status"`
	Details map[string]interface{} `json:"details,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// Metadata contains response metadata
type Metadata struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// Checker manages health checks
type Checker struct {
	startTime time.Time
	checks    []*Check
	mu        sync.RWMutex
}

// New creates a new health checker
func New() *Checker {
	return &Checker{
		checks:    make([]*Check, 0),
		startTime: time.Now(),
	}
}

// AddCheck adds a health check
func (c *Checker) AddCheck(name string, fn func(context.Context) (Status, string)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.checks = append(c.checks, &Check{
		Name: name,
		Fn:   fn,
	})
}

// RunChecks runs all health checks
func (c *Checker) RunChecks(ctx context.Context) *HealthData {
	c.mu.RLock()
	checks := make([]*Check, len(c.checks))
	copy(checks, c.checks)
	c.mu.RUnlock()

	components := make(map[string]*Component)
	overallStatus := StatusHealthy

	for _, check := range checks {
		status, errMsg := check.Fn(ctx)
		components[check.Name] = &Component{
			Status: status,
			Error:  errMsg,
		}

		// Determine overall status
		if status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
	}

	return &HealthData{
		Status:     overallStatus,
		Version:    version.Version,
		Uptime:     time.Since(c.startTime).String(),
		Components: components,
	}
}

// HealthHandler returns an HTTP handler for health checks
func (c *Checker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		healthData := c.RunChecks(ctx)

		response := Response{
			Success: healthData.Status == StatusHealthy,
			Data:    healthData,
			Metadata: &Metadata{
				RequestID: r.Header.Get("X-Request-ID"),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		}

		statusCode := http.StatusOK
		if healthData.Status == StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		} else if healthData.Status == StatusDegraded {
			statusCode = http.StatusOK // 200 but degraded
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(response) // #nosec G104 -- JSON response write
	}
}

// ReadyHandler returns an HTTP handler for readiness checks
func (c *Checker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		healthData := c.RunChecks(ctx)

		ready := healthData.Status != StatusUnhealthy

		response := Response{
			Success: ready,
			Data: &HealthData{
				Status:     healthData.Status,
				Components: healthData.Components,
			},
			Metadata: &Metadata{
				RequestID: r.Header.Get("X-Request-ID"),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		}

		statusCode := http.StatusOK
		if !ready {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(response) // #nosec G104 -- JSON response write
	}
}
