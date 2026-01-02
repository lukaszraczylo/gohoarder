package app

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// requireAdmin middleware checks for admin authentication
func (a *App) requireAdmin(c *fiber.Ctx) error {
	// Get API key from Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "missing authorization header",
		})
	}

	// Extract bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid authorization header format, expected: Bearer <token>",
		})
	}

	apiKey := parts[1]

	// Validate API key
	key, err := a.authManager.ValidateAPIKey(c.Context(), apiKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid or expired API key",
		})
	}

	// Check if user has admin role or bypass management permission
	if key.Role != auth.RoleAdmin && !key.HasPermission(auth.PermissionManageBypasses) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "insufficient permissions, admin role required",
		})
	}

	// Continue to next handler
	return c.Next()
}

// handleAdminBypasses handles /api/admin/bypasses endpoint
func (a *App) handleAdminBypasses(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	// Check if there's an ID parameter
	id := c.Params("id")

	switch c.Method() {
	case "GET":
		if id != "" {
			return a.handleGetBypass(c)
		}
		return a.handleListBypasses(c)
	case "POST":
		return a.handleCreateBypass(c)
	case "PATCH":
		return a.handleUpdateBypass(c)
	case "DELETE":
		return a.handleDeleteBypass(c)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}
}

// handleListBypasses lists all CVE bypasses
func (a *App) handleListBypasses(c *fiber.Ctx) error {
	ctx := c.Context()

	// Parse query parameters
	includeExpired := c.Query("include_expired") == "true"
	activeOnly := c.Query("active_only") == "true"
	bypassType := metadata.BypassType(c.Query("type"))

	opts := &metadata.BypassListOptions{
		IncludeExpired: includeExpired,
		ActiveOnly:     activeOnly,
		Type:           bypassType,
	}

	bypasses, err := a.metadata.ListCVEBypasses(ctx, opts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list CVE bypasses")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list bypasses"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"bypasses": bypasses,
		"total":    len(bypasses),
	})
}

// CreateBypassRequest represents the request body for creating a bypass
type CreateBypassRequest struct {
	Type           metadata.BypassType `json:"type"`                 // "cve" or "package"
	Target         string              `json:"target"`               // CVE ID or package name
	Reason         string              `json:"reason"`               // Why this bypass is needed
	CreatedBy      string              `json:"created_by"`           // Admin username
	ExpiresInHours int                 `json:"expires_in_hours"`     // How many hours until expiration
	AppliesTo      string              `json:"applies_to,omitempty"` // Optional: limit CVE bypass to specific package
	NotifyOnExpiry bool                `json:"notify_on_expiry"`     // Send notification when expired
}

// handleCreateBypass creates a new CVE bypass
func (a *App) handleCreateBypass(c *fiber.Ctx) error {
	ctx := c.Context()

	var req CreateBypassRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON in request body"})
	}

	// Validate request
	if req.Type != metadata.BypassTypeCVE && req.Type != metadata.BypassTypePackage {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "type must be 'cve' or 'package'"})
	}

	if req.Target == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "target is required"})
	}

	if req.Reason == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "reason is required"})
	}

	if req.CreatedBy == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "created_by is required"})
	}

	if req.ExpiresInHours <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "expires_in_hours must be greater than 0"})
	}

	// Create bypass
	now := time.Now()
	expiresAt := now.Add(time.Duration(req.ExpiresInHours) * time.Hour)

	bypass := &metadata.CVEBypass{
		ID:             uuid.New().String(),
		Type:           req.Type,
		Target:         req.Target,
		Reason:         req.Reason,
		CreatedBy:      req.CreatedBy,
		CreatedAt:      now,
		ExpiresAt:      expiresAt,
		AppliesTo:      req.AppliesTo,
		NotifyOnExpiry: req.NotifyOnExpiry,
		Active:         true,
	}

	// Save to database
	if err := a.metadata.SaveCVEBypass(ctx, bypass); err != nil {
		log.Error().Err(err).Msg("Failed to save CVE bypass")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create bypass"})
	}

	log.Info().
		Str("bypass_id", bypass.ID).
		Str("type", string(bypass.Type)).
		Str("target", bypass.Target).
		Str("created_by", bypass.CreatedBy).
		Time("expires_at", bypass.ExpiresAt).
		Msg("CVE bypass created")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"bypass":  bypass,
		"message": "Bypass created successfully",
	})
}

// handleGetBypass gets a specific bypass by ID
func (a *App) handleGetBypass(c *fiber.Ctx) error {
	ctx := c.Context()

	// Extract ID from parameter
	bypassID := c.Params("id")

	if bypassID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "bypass ID is required"})
	}

	// Get all bypasses and find the one with matching ID
	bypasses, err := a.metadata.ListCVEBypasses(ctx, &metadata.BypassListOptions{
		IncludeExpired: true,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list bypasses")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get bypass"})
	}

	for _, bypass := range bypasses {
		if bypass.ID == bypassID {
			return c.Status(fiber.StatusOK).JSON(fiber.Map{
				"bypass": bypass,
			})
		}
	}

	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "bypass not found"})
}

// UpdateBypassRequest represents the request body for updating a bypass
type UpdateBypassRequest struct {
	Active         *bool  `json:"active,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ExpiresInHours int    `json:"expires_in_hours,omitempty"`
}

// handleUpdateBypass updates a bypass (activate/deactivate or extend expiration)
func (a *App) handleUpdateBypass(c *fiber.Ctx) error {
	ctx := c.Context()

	// Extract ID from parameter
	bypassID := c.Params("id")

	if bypassID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "bypass ID is required"})
	}

	var req UpdateBypassRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON in request body"})
	}

	// Get current bypass
	bypasses, err := a.metadata.ListCVEBypasses(ctx, &metadata.BypassListOptions{
		IncludeExpired: true,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list bypasses")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get bypass"})
	}

	var currentBypass *metadata.CVEBypass
	for _, bypass := range bypasses {
		if bypass.ID == bypassID {
			currentBypass = bypass
			break
		}
	}

	if currentBypass == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "bypass not found"})
	}

	// Update fields
	if req.Active != nil {
		currentBypass.Active = *req.Active
	}

	if req.Reason != "" {
		currentBypass.Reason = req.Reason
	}

	if req.ExpiresInHours > 0 {
		currentBypass.ExpiresAt = time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
	}

	// Save updated bypass
	if err := a.metadata.SaveCVEBypass(ctx, currentBypass); err != nil {
		log.Error().Err(err).Msg("Failed to update bypass")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update bypass"})
	}

	log.Info().
		Str("bypass_id", currentBypass.ID).
		Bool("active", currentBypass.Active).
		Msg("CVE bypass updated")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"bypass":  currentBypass,
		"message": "Bypass updated successfully",
	})
}

// handleDeleteBypass deletes a bypass
func (a *App) handleDeleteBypass(c *fiber.Ctx) error {
	ctx := c.Context()

	// Extract ID from parameter
	bypassID := c.Params("id")

	if bypassID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "bypass ID is required"})
	}

	// Delete bypass
	if err := a.metadata.DeleteCVEBypass(ctx, bypassID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "bypass not found"})
		}
		log.Error().Err(err).Msg("Failed to delete bypass")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete bypass"})
	}

	log.Info().
		Str("bypass_id", bypassID).
		Msg("CVE bypass deleted")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"deleted":   true,
		"bypass_id": bypassID,
		"message":   "Bypass deleted successfully",
	})
}
