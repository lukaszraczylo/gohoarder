package app

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/stretchr/testify/suite"
)

type AnalyticsHandlersTestSuite struct {
	suite.Suite
	app     *fiber.App
	appInst *App
	engine  *analytics.Engine
}

func (s *AnalyticsHandlersTestSuite) SetupTest() {
	// Create analytics engine
	s.engine = analytics.NewEngine(analytics.Config{
		MaxEvents:     10000,
		FlushInterval: 5 * time.Minute,
	})

	// Seed some test data
	s.engine.TrackDownload(analytics.PackageDownload{
		Registry:  "npm",
		Name:      "lodash",
		Version:   "4.17.21",
		Timestamp: time.Now(),
		BytesSize: 1024,
	})
	s.engine.TrackDownload(analytics.PackageDownload{
		Registry:  "npm",
		Name:      "react",
		Version:   "18.0.0",
		Timestamp: time.Now(),
		BytesSize: 2048,
	})
	s.engine.TrackDownload(analytics.PackageDownload{
		Registry:  "pypi",
		Name:      "requests",
		Version:   "2.28.0",
		Timestamp: time.Now(),
		BytesSize: 512,
	})

	// Create app instance
	s.appInst = &App{
		analyticsEngine: s.engine,
	}

	// Create Fiber app
	s.app = fiber.New()

	// Register routes
	s.app.Get("/api/analytics/top", s.appInst.handleAnalyticsTopPackages)
	s.app.Get("/api/analytics/trending", s.appInst.handleAnalyticsTrendingPackages)
	s.app.Get("/api/analytics/trends", s.appInst.handleAnalyticsTrends)
	s.app.Get("/api/analytics/total", s.appInst.handleAnalyticsTotalStats)
	s.app.Get("/api/analytics/registry/:registry", s.appInst.handleAnalyticsRegistryStats)
	s.app.Get("/api/analytics/package/:registry/:name", s.appInst.handleAnalyticsPackageStats)
	s.app.Get("/api/analytics/search", s.appInst.handleAnalyticsSearch)
}

func (s *AnalyticsHandlersTestSuite) TearDownTest() {
	if s.engine != nil {
		s.engine.Close()
	}
}

func TestAnalyticsHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AnalyticsHandlersTestSuite))
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsTopPackages() {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "get top packages default",
			queryParams:    "",
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:           "get top packages with limit",
			queryParams:    "?limit=5",
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:           "get top packages with registry filter",
			queryParams:    "?registry=npm",
			expectedStatus: 200,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest("GET", "/api/analytics/top"+tt.queryParams, nil)
			resp, err := s.app.Test(req)
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)

			if !tt.expectError {
				var result struct {
					Packages []analytics.PackageStats `json:"packages"`
					Total    int                      `json:"total"`
				}
				err = json.NewDecoder(resp.Body).Decode(&result)
				s.NoError(err)
			}
		})
	}
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsTrendingPackages() {
	req := httptest.NewRequest("GET", "/api/analytics/trending", nil)
	resp, err := s.app.Test(req)
	s.Require().NoError(err)
	s.Equal(200, resp.StatusCode)

	var result struct {
		Packages []analytics.PackageStats `json:"packages"`
		Total    int                      `json:"total"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	s.NoError(err)
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsTrends() {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
		{
			name:           "get trends default timeframe",
			queryParams:    "",
			expectedStatus: 200,
		},
		{
			name:           "get trends with registry filter",
			queryParams:    "?registry=npm",
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest("GET", "/api/analytics/trends"+tt.queryParams, nil)
			resp, err := s.app.Test(req)
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)
		})
	}
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsTotalStats() {
	req := httptest.NewRequest("GET", "/api/analytics/total", nil)
	resp, err := s.app.Test(req)
	s.Require().NoError(err)
	s.Equal(200, resp.StatusCode)

	var result struct {
		TotalDownloads int64 `json:"total_downloads"`
		TotalBytes     int64 `json:"total_bytes"`
		UniquePackages int   `json:"unique_packages"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	s.NoError(err)
	s.Greater(result.TotalDownloads, int64(0))
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsRegistryStats() {
	tests := []struct {
		name           string
		registry       string
		expectedStatus int
	}{
		{
			name:           "npm registry stats",
			registry:       "npm",
			expectedStatus: 200,
		},
		{
			name:           "pypi registry stats",
			registry:       "pypi",
			expectedStatus: 200,
		},
		{
			name:           "go registry stats",
			registry:       "go",
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest("GET", "/api/analytics/registry/"+tt.registry, nil)
			resp, err := s.app.Test(req)
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)
		})
	}
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsPackageStats() {
	tests := []struct {
		name           string
		registry       string
		packageName    string
		expectedStatus int
	}{
		{
			name:           "lodash package stats",
			registry:       "npm",
			packageName:    "lodash",
			expectedStatus: 200,
		},
		{
			name:           "react package stats",
			registry:       "npm",
			packageName:    "react",
			expectedStatus: 200,
		},
		{
			name:           "requests package stats",
			registry:       "pypi",
			packageName:    "requests",
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest("GET", "/api/analytics/package/"+tt.registry+"/"+tt.packageName, nil)
			resp, err := s.app.Test(req)
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)
		})
	}
}

func (s *AnalyticsHandlersTestSuite) TestHandleAnalyticsSearch() {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "search for lodash",
			queryParams:    "?q=lodash",
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:           "search for react",
			queryParams:    "?q=react",
			expectedStatus: 200,
			expectError:    false,
		},
		{
			name:           "search with no query",
			queryParams:    "",
			expectedStatus: 400, // Query parameter is required
			expectError:    true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest("GET", "/api/analytics/search"+tt.queryParams, nil)
			resp, err := s.app.Test(req)
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)

			if !tt.expectError {
				var result struct {
					Results []analytics.PackageStats `json:"results"`
					Total   int                      `json:"total"`
					Query   string                   `json:"query"`
				}
				err = json.NewDecoder(resp.Body).Decode(&result)
				s.NoError(err)
			}
		})
	}
}
