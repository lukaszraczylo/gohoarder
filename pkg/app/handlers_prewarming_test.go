package app

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/prewarming"
	"github.com/stretchr/testify/suite"
)

type PrewarmingHandlersTestSuite struct {
	suite.Suite
	app           *fiber.App
	appInst       *App
	prewarmWorker *prewarming.Worker
}

func (s *PrewarmingHandlersTestSuite) SetupTest() {
	// Create pre-warming worker (disabled by default)
	s.prewarmWorker = prewarming.NewWorker(prewarming.Config{
		Enabled:       false,
		MaxConcurrent: 5,
	})

	// Create app instance
	s.appInst = &App{
		prewarmWorker: s.prewarmWorker,
	}

	// Create Fiber app
	s.app = fiber.New()

	// Register routes
	s.app.Get("/api/admin/prewarming/status", s.appInst.handlePrewarmingStatus)
	s.app.Post("/api/admin/prewarming/trigger", s.appInst.handlePrewarmingTrigger)
	s.app.Post("/api/admin/prewarming/package", s.appInst.handlePrewarmingPackage)
}

func (s *PrewarmingHandlersTestSuite) TearDownTest() {
	if s.prewarmWorker != nil {
		s.prewarmWorker.Stop()
	}
}

func TestPrewarmingHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(PrewarmingHandlersTestSuite))
}

func (s *PrewarmingHandlersTestSuite) TestHandlePrewarmingStatus() {
	req := httptest.NewRequest("GET", "/api/admin/prewarming/status", nil)
	resp, err := s.app.Test(req)
	s.Require().NoError(err)
	s.Equal(200, resp.StatusCode)

	var result struct {
		Enabled       bool `json:"enabled"`
		Running       bool `json:"running"`
		QueueSize     int  `json:"queue_size"`
		ActiveWorkers int  `json:"active_workers"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	s.NoError(err)
	s.False(result.Enabled) // Disabled in test setup
}

func (s *PrewarmingHandlersTestSuite) TestHandlePrewarmingTrigger() {
	req := httptest.NewRequest("POST", "/api/admin/prewarming/trigger", nil)
	resp, err := s.app.Test(req)
	s.Require().NoError(err)
	s.Equal(200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	s.NoError(err)
	s.Contains(result, "message")
}

func (s *PrewarmingHandlersTestSuite) TestHandlePrewarmingPackage() {
	tests := []struct {
		requestBody    map[string]string
		name           string
		expectedStatus int
	}{
		{
			name: "prewarm npm package",
			requestBody: map[string]string{
				"registry": "npm",
				"name":     "lodash",
				"version":  "4.17.21",
			},
			expectedStatus: 200,
		},
		{
			name: "prewarm pypi package",
			requestBody: map[string]string{
				"registry": "pypi",
				"name":     "requests",
				"version":  "2.28.0",
			},
			expectedStatus: 200,
		},
		{
			name: "prewarm go package",
			requestBody: map[string]string{
				"registry": "go",
				"name":     "github.com/stretchr/testify",
				"version":  "v1.8.0",
			},
			expectedStatus: 200,
		},
		{
			name: "missing registry",
			requestBody: map[string]string{
				"name":    "lodash",
				"version": "4.17.21",
			},
			expectedStatus: 400,
		},
		{
			name: "missing name",
			requestBody: map[string]string{
				"registry": "npm",
				"version":  "4.17.21",
			},
			expectedStatus: 400,
		},
		{
			name: "missing version",
			requestBody: map[string]string{
				"registry": "npm",
				"name":     "lodash",
			},
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			bodyBytes, err := json.Marshal(tt.requestBody)
			s.Require().NoError(err)

			req := httptest.NewRequest("POST", "/api/admin/prewarming/package", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := s.app.Test(req)
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)
		})
	}
}

func (s *PrewarmingHandlersTestSuite) TestHandlePrewarmingPackageInvalidJSON() {
	req := httptest.NewRequest("POST", "/api/admin/prewarming/package", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.app.Test(req)
	s.Require().NoError(err)
	s.Equal(400, resp.StatusCode)
}
