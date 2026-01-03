package app

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/rs/zerolog/log"
)

// GenerateAPIKeyRequest represents a request to generate a new API key
type GenerateAPIKeyRequest struct {
	ExpiresInMin *int   `json:"expires_in_min"`
	Name         string `json:"name"`
	Role         string `json:"role"`
}

// handleGenerateAPIKey generates a new API key
func (a *App) handleGenerateAPIKey(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	var req GenerateAPIKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid JSON in request body",
		})
	}

	// Validate request
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name is required",
		})
	}

	// Parse role (default to readonly if not specified)
	var role auth.Role
	switch req.Role {
	case "admin":
		role = auth.RoleAdmin
	case "readwrite":
		role = auth.RoleReadWrite
	case "readonly", "":
		role = auth.RoleReadOnly
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid role, must be 'admin', 'readwrite', or 'readonly'",
		})
	}

	// Calculate expiration
	var expiresIn *time.Duration
	if req.ExpiresInMin != nil {
		duration := time.Duration(*req.ExpiresInMin) * time.Minute
		expiresIn = &duration
	}

	// Generate key
	apiKey, rawKey, err := a.authManager.GenerateAPIKey(req.Name, role, expiresIn)
	if err != nil {
		log.Error().Err(err).Str("name", req.Name).Msg("Failed to generate API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to generate API key",
		})
	}

	log.Info().
		Str("key_id", apiKey.ID).
		Str("name", apiKey.Name).
		Str("role", string(apiKey.Role)).
		Msg("API key generated")

	// Return the key info and raw key (only time it's shown!)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"key":     rawKey, // IMPORTANT: This is the only time the raw key is shown
		"key_id":  apiKey.ID,
		"name":    apiKey.Name,
		"role":    apiKey.Role,
		"expires": apiKey.ExpiresAt,
		"message": "Save this key now! It will not be shown again.",
	})
}

// handleListAPIKeys lists all API keys
func (a *App) handleListAPIKeys(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	keys := a.authManager.ListAPIKeys()

	// Convert to response format (excluding hashed keys)
	response := make([]fiber.Map, len(keys))
	for i, key := range keys {
		response[i] = fiber.Map{
			"id":           key.ID,
			"name":         key.Name,
			"role":         key.Role,
			"created_at":   key.CreatedAt,
			"expires_at":   key.ExpiresAt,
			"last_used_at": key.LastUsedAt,
			"permissions":  key.Permissions,
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"keys":  response,
		"total": len(response),
	})
}

// handleRevokeAPIKey revokes an API key
func (a *App) handleRevokeAPIKey(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	keyID := c.Params("key_id")
	if keyID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "key_id parameter is required",
		})
	}

	err := a.authManager.RevokeAPIKey(keyID)
	if err != nil {
		log.Warn().Err(err).Str("key_id", keyID).Msg("Failed to revoke API key")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "API key not found",
		})
	}

	log.Info().Str("key_id", keyID).Msg("API key revoked")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "API key revoked successfully",
		"key_id":  keyID,
	})
}
