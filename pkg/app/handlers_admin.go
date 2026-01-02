package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// requireAdmin middleware checks for admin authentication
func (a *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get API key from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			errors.WriteErrorSimple(w, errors.New(errors.ErrCodeUnauthorized, "missing authorization header"))
			return
		}

		// Extract bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			errors.WriteErrorSimple(w, errors.New(errors.ErrCodeUnauthorized, "invalid authorization header format, expected: Bearer <token>"))
			return
		}

		apiKey := parts[1]

		// Validate API key
		key, err := a.authManager.ValidateAPIKey(r.Context(), apiKey)
		if err != nil {
			errors.WriteErrorSimple(w, errors.New(errors.ErrCodeUnauthorized, "invalid or expired API key"))
			return
		}

		// Check if user has admin role or bypass management permission
		if key.Role != auth.RoleAdmin && !key.HasPermission(auth.PermissionManageBypasses) {
			errors.WriteErrorSimple(w, errors.New(errors.ErrCodeForbidden, "insufficient permissions, admin role required"))
			return
		}

		// Store user info in request context for handlers to use
		// For now, we'll just proceed - could enhance with context.WithValue
		next(w, r)
	}
}

// handleAdminBypasses handles /api/admin/bypasses endpoint
func (a *App) handleAdminBypasses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case "GET":
		a.requireAdmin(a.handleListBypasses)(w, r)
	case "POST":
		a.requireAdmin(a.handleCreateBypass)(w, r)
	default:
		errors.WriteErrorSimple(w, errors.BadRequest("method not allowed"))
	}
}

// handleBypassByID handles /api/admin/bypasses/{id} endpoint
func (a *App) handleBypassByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case "GET":
		a.requireAdmin(a.handleGetBypass)(w, r)
	case "DELETE":
		a.requireAdmin(a.handleDeleteBypass)(w, r)
	case "PATCH":
		a.requireAdmin(a.handleUpdateBypass)(w, r)
	default:
		errors.WriteErrorSimple(w, errors.BadRequest("method not allowed"))
	}
}

// handleListBypasses lists all CVE bypasses
func (a *App) handleListBypasses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	includeExpired := r.URL.Query().Get("include_expired") == "true"
	activeOnly := r.URL.Query().Get("active_only") == "true"
	bypassType := metadata.BypassType(r.URL.Query().Get("type"))

	opts := &metadata.BypassListOptions{
		IncludeExpired: includeExpired,
		ActiveOnly:     activeOnly,
		Type:           bypassType,
	}

	bypasses, err := a.metadata.ListCVEBypasses(ctx, opts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list CVE bypasses")
		errors.WriteErrorSimple(w, errors.InternalServer("failed to list bypasses"))
		return
	}

	errors.WriteJSONSimple(w, http.StatusOK, map[string]interface{}{
		"bypasses": bypasses,
		"total":    len(bypasses),
	})
}

// CreateBypassRequest represents the request body for creating a bypass
type CreateBypassRequest struct {
	Type           metadata.BypassType `json:"type"`            // "cve" or "package"
	Target         string              `json:"target"`          // CVE ID or package name
	Reason         string              `json:"reason"`          // Why this bypass is needed
	CreatedBy      string              `json:"created_by"`      // Admin username
	ExpiresInHours int                 `json:"expires_in_hours"` // How many hours until expiration
	AppliesTo      string              `json:"applies_to,omitempty"` // Optional: limit CVE bypass to specific package
	NotifyOnExpiry bool                `json:"notify_on_expiry"` // Send notification when expired
}

// handleCreateBypass creates a new CVE bypass
func (a *App) handleCreateBypass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errors.WriteErrorSimple(w, errors.BadRequest("failed to read request body"))
		return
	}
	defer r.Body.Close()

	var req CreateBypassRequest
	if err := json.Unmarshal(body, &req); err != nil {
		errors.WriteErrorSimple(w, errors.BadRequest("invalid JSON in request body"))
		return
	}

	// Validate request
	if req.Type != metadata.BypassTypeCVE && req.Type != metadata.BypassTypePackage {
		errors.WriteErrorSimple(w, errors.BadRequest("type must be 'cve' or 'package'"))
		return
	}

	if req.Target == "" {
		errors.WriteErrorSimple(w, errors.BadRequest("target is required"))
		return
	}

	if req.Reason == "" {
		errors.WriteErrorSimple(w, errors.BadRequest("reason is required"))
		return
	}

	if req.CreatedBy == "" {
		errors.WriteErrorSimple(w, errors.BadRequest("created_by is required"))
		return
	}

	if req.ExpiresInHours <= 0 {
		errors.WriteErrorSimple(w, errors.BadRequest("expires_in_hours must be greater than 0"))
		return
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
		errors.WriteErrorSimple(w, errors.InternalServer("failed to create bypass"))
		return
	}

	log.Info().
		Str("bypass_id", bypass.ID).
		Str("type", string(bypass.Type)).
		Str("target", bypass.Target).
		Str("created_by", bypass.CreatedBy).
		Time("expires_at", bypass.ExpiresAt).
		Msg("CVE bypass created")

	errors.WriteJSONSimple(w, http.StatusCreated, map[string]interface{}{
		"bypass":  bypass,
		"message": "Bypass created successfully",
	})
}

// handleGetBypass gets a specific bypass by ID
func (a *App) handleGetBypass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/bypasses/")
	bypassID := path

	if bypassID == "" {
		errors.WriteErrorSimple(w, errors.BadRequest("bypass ID is required"))
		return
	}

	// Get all bypasses and find the one with matching ID
	bypasses, err := a.metadata.ListCVEBypasses(ctx, &metadata.BypassListOptions{
		IncludeExpired: true,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list bypasses")
		errors.WriteErrorSimple(w, errors.InternalServer("failed to get bypass"))
		return
	}

	for _, bypass := range bypasses {
		if bypass.ID == bypassID {
			errors.WriteJSONSimple(w, http.StatusOK, map[string]interface{}{
				"bypass": bypass,
			})
			return
		}
	}

	errors.WriteErrorSimple(w, errors.NotFound("bypass not found"))
}

// UpdateBypassRequest represents the request body for updating a bypass
type UpdateBypassRequest struct {
	Active         *bool  `json:"active,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ExpiresInHours int    `json:"expires_in_hours,omitempty"`
}

// handleUpdateBypass updates a bypass (activate/deactivate or extend expiration)
func (a *App) handleUpdateBypass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/bypasses/")
	bypassID := path

	if bypassID == "" {
		errors.WriteErrorSimple(w, errors.BadRequest("bypass ID is required"))
		return
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errors.WriteErrorSimple(w, errors.BadRequest("failed to read request body"))
		return
	}
	defer r.Body.Close()

	var req UpdateBypassRequest
	if err := json.Unmarshal(body, &req); err != nil {
		errors.WriteErrorSimple(w, errors.BadRequest("invalid JSON in request body"))
		return
	}

	// Get current bypass
	bypasses, err := a.metadata.ListCVEBypasses(ctx, &metadata.BypassListOptions{
		IncludeExpired: true,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list bypasses")
		errors.WriteErrorSimple(w, errors.InternalServer("failed to get bypass"))
		return
	}

	var currentBypass *metadata.CVEBypass
	for _, bypass := range bypasses {
		if bypass.ID == bypassID {
			currentBypass = bypass
			break
		}
	}

	if currentBypass == nil {
		errors.WriteErrorSimple(w, errors.NotFound("bypass not found"))
		return
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
		errors.WriteErrorSimple(w, errors.InternalServer("failed to update bypass"))
		return
	}

	log.Info().
		Str("bypass_id", currentBypass.ID).
		Bool("active", currentBypass.Active).
		Msg("CVE bypass updated")

	errors.WriteJSONSimple(w, http.StatusOK, map[string]interface{}{
		"bypass":  currentBypass,
		"message": "Bypass updated successfully",
	})
}

// handleDeleteBypass deletes a bypass
func (a *App) handleDeleteBypass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/bypasses/")
	bypassID := path

	if bypassID == "" {
		errors.WriteErrorSimple(w, errors.BadRequest("bypass ID is required"))
		return
	}

	// Delete bypass
	if err := a.metadata.DeleteCVEBypass(ctx, bypassID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			errors.WriteErrorSimple(w, errors.NotFound("bypass not found"))
		} else {
			log.Error().Err(err).Msg("Failed to delete bypass")
			errors.WriteErrorSimple(w, errors.InternalServer("failed to delete bypass"))
		}
		return
	}

	log.Info().
		Str("bypass_id", bypassID).
		Msg("CVE bypass deleted")

	errors.WriteJSONSimple(w, http.StatusOK, map[string]interface{}{
		"deleted": true,
		"bypass_id": bypassID,
		"message": "Bypass deleted successfully",
	})
}
