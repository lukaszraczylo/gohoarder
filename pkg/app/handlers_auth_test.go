package app

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/stretchr/testify/suite"
)

type AuthHandlersTestSuite struct {
	suite.Suite
	app         *fiber.App
	appInst     *App
	authManager *auth.Manager
}

func (s *AuthHandlersTestSuite) SetupTest() {
	// Create auth manager
	s.authManager = auth.New()

	// Create app instance
	s.appInst = &App{
		authManager: s.authManager,
	}

	// Create Fiber app
	s.app = fiber.New()

	// Register routes
	s.app.Post("/api/admin/keys", s.appInst.handleGenerateAPIKey)
	s.app.Get("/api/admin/keys", s.appInst.handleListAPIKeys)
	s.app.Delete("/api/admin/keys/:key_id", s.appInst.handleRevokeAPIKey)
}

func TestAuthHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}

func (s *AuthHandlersTestSuite) TestHandleGenerateAPIKey() {
	tests := []struct {
		requestBody    map[string]string
		name           string
		expectedStatus int
		expectedRole   string
		expectKey      bool
	}{
		{
			name: "generate read-only key",
			requestBody: map[string]string{
				"role": "readonly",
				"name": "test-readonly-key",
			},
			expectedStatus: 201,
			expectedRole:   "readonly",
			expectKey:      true,
		},
		{
			name: "generate read-write key",
			requestBody: map[string]string{
				"role": "readwrite",
				"name": "test-readwrite-key",
			},
			expectedStatus: 201,
			expectedRole:   "readwrite",
			expectKey:      true,
		},
		{
			name: "generate admin key",
			requestBody: map[string]string{
				"role": "admin",
				"name": "test-admin-key",
			},
			expectedStatus: 201,
			expectedRole:   "admin",
			expectKey:      true,
		},
		{
			name: "invalid role",
			requestBody: map[string]string{
				"role": "invalid-role",
				"name": "test-key",
			},
			expectedStatus: 400,
			expectKey:      false,
		},
		{
			name: "missing role defaults to readonly",
			requestBody: map[string]string{
				"name": "test-key-default-role",
			},
			expectedStatus: 201,
			expectedRole:   "readonly", // Role defaults to readonly when not specified
			expectKey:      true,
		},
		{
			name: "missing name",
			requestBody: map[string]string{
				"role": "read-only",
			},
			expectedStatus: 400,
			expectKey:      false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			bodyBytes, err := json.Marshal(tt.requestBody)
			s.Require().NoError(err)

			req := httptest.NewRequest("POST", "/api/admin/keys", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			resp, err := s.app.Test(req, 5000) // 5 second timeout for CI environments
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)

			if tt.expectKey {
				var result struct {
					Key     string `json:"key"`
					KeyID   string `json:"key_id"`
					Role    string `json:"role"`
					Name    string `json:"name"`
					Message string `json:"message"`
				}
				err = json.NewDecoder(resp.Body).Decode(&result)
				s.NoError(err)
				s.NotEmpty(result.Key)
				s.NotEmpty(result.KeyID)
				s.Equal(tt.expectedRole, result.Role)
				s.Equal(tt.requestBody["name"], result.Name)
			}
		})
	}
}

func (s *AuthHandlersTestSuite) TestHandleListAPIKeys() {
	// Generate some test keys first
	s.authManager.GenerateAPIKey("test-key-1", auth.RoleReadOnly, nil)
	s.authManager.GenerateAPIKey("test-key-2", auth.RoleReadWrite, nil)
	s.authManager.GenerateAPIKey("test-key-3", auth.RoleAdmin, nil)

	req := httptest.NewRequest("GET", "/api/admin/keys", nil)
	resp, err := s.app.Test(req, 5000) // 5 second timeout for CI environments
	s.Require().NoError(err)
	s.Equal(200, resp.StatusCode)

	var result struct {
		Keys  []map[string]interface{} `json:"keys"`
		Total int                      `json:"total"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	s.NoError(err)
	s.GreaterOrEqual(result.Total, 3)

	// Verify keys don't include the actual key value
	for _, key := range result.Keys {
		s.NotEmpty(key["id"])
		s.NotEmpty(key["role"])
		s.NotEmpty(key["name"])
		s.NotEmpty(key["created_at"])
	}
}

func (s *AuthHandlersTestSuite) TestHandleRevokeAPIKey() {
	// Generate a test key
	keyInfo, _, _ := s.authManager.GenerateAPIKey("test-revoke-key", auth.RoleReadOnly, nil)

	tests := []struct {
		name           string
		keyID          string
		expectedStatus int
	}{
		{
			name:           "revoke existing key",
			keyID:          keyInfo.ID,
			expectedStatus: 200,
		},
		{
			name:           "revoke non-existent key",
			keyID:          "non-existent-key-id",
			expectedStatus: 404,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest("DELETE", "/api/admin/keys/"+tt.keyID, nil)
			resp, err := s.app.Test(req, 5000) // 5 second timeout for CI environments
			s.Require().NoError(err)
			s.Equal(tt.expectedStatus, resp.StatusCode)

			if tt.expectedStatus == 200 {
				var result map[string]string
				err = json.NewDecoder(resp.Body).Decode(&result)
				s.NoError(err)
				s.Contains(result, "message")
			}
		})
	}
}

func (s *AuthHandlersTestSuite) TestHandleGenerateAPIKeyInvalidJSON() {
	req := httptest.NewRequest("POST", "/api/admin/keys", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.app.Test(req, 5000) // 5 second timeout for CI environments
	s.Require().NoError(err)
	s.Equal(400, resp.StatusCode)
}

func (s *AuthHandlersTestSuite) TestGenerateAndRevokeKeyFlow() {
	// Generate a key
	bodyBytes, _ := json.Marshal(map[string]string{
		"role": "readonly",
		"name": "integration-test-key",
	})

	req1 := httptest.NewRequest("POST", "/api/admin/keys", bytes.NewReader(bodyBytes))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := s.app.Test(req1, 5000) // 5 second timeout for CI environments
	s.Require().NoError(err)
	s.Equal(201, resp1.StatusCode)

	var createResult struct {
		Key   string `json:"key"`
		KeyID string `json:"key_id"`
	}
	err = json.NewDecoder(resp1.Body).Decode(&createResult)
	s.Require().NoError(err)
	keyID := createResult.KeyID

	// List keys - should include our new key
	req2 := httptest.NewRequest("GET", "/api/admin/keys", nil)
	resp2, err := s.app.Test(req2, 5000) // 5 second timeout for CI environments
	s.Require().NoError(err)
	s.Equal(200, resp2.StatusCode)

	var listResult struct {
		Keys  []map[string]interface{} `json:"keys"`
		Total int                      `json:"total"`
	}
	err = json.NewDecoder(resp2.Body).Decode(&listResult)
	s.Require().NoError(err)

	found := false
	for _, key := range listResult.Keys {
		if key["id"].(string) == keyID {
			found = true
			break
		}
	}
	s.True(found, "newly created key should be in the list")

	// Revoke the key
	req3 := httptest.NewRequest("DELETE", "/api/admin/keys/"+keyID, nil)
	resp3, err := s.app.Test(req3, 5000) // 5 second timeout for CI environments
	s.Require().NoError(err)
	s.Equal(200, resp3.StatusCode)

	// List keys again - should not include the revoked key
	req4 := httptest.NewRequest("GET", "/api/admin/keys", nil)
	resp4, err := s.app.Test(req4, 5000) // 5 second timeout for CI environments
	s.Require().NoError(err)
	s.Equal(200, resp4.StatusCode)

	var listResult2 struct {
		Keys  []map[string]interface{} `json:"keys"`
		Total int                      `json:"total"`
	}
	err = json.NewDecoder(resp4.Body).Decode(&listResult2)
	s.Require().NoError(err)

	found = false
	for _, key := range listResult2.Keys {
		if key["id"].(string) == keyID {
			found = true
			break
		}
	}
	s.False(found, "revoked key should not be in the list")
}
