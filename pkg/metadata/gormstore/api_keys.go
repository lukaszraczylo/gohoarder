package gormstore

import (
	"context"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SaveAPIKey persists an API key. Insert-or-update by primary key.
func (s *GORMStoreV2) SaveAPIKey(ctx context.Context, key *metadata.APIKey) error {
	if key == nil || key.ID == "" {
		return errors.New(errors.ErrCodeBadRequest, "api key id required")
	}

	model := &APIKeyModel{
		ID:          key.ID,
		KeyHash:     key.KeyHash,
		Project:     key.Project,
		Role:        key.Role,
		Permissions: key.Permissions,
		CreatedAt:   key.CreatedAt,
		ExpiresAt:   key.ExpiresAt,
		LastUsedAt:  key.LastUsedAt,
		Revoked:     key.Revoked,
	}
	if model.CreatedAt.IsZero() {
		model.CreatedAt = time.Now()
	}

	// Upsert on primary key. Updates all columns on conflict — keeps the call
	// site simple (Generate then Revoke both flow through here).
	err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).
		Create(model).Error
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save api key")
	}
	return nil
}

// GetAPIKey retrieves an API key by ID. Returns a not-found error if missing.
func (s *GORMStoreV2) GetAPIKey(ctx context.Context, id string) (*metadata.APIKey, error) {
	var model APIKeyModel
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&model).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeNotFound, "api key not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get api key")
	}
	return apiKeyModelToMetadata(&model), nil
}

// ListAPIKeys returns all API keys (revoked included). Caller filters as needed.
func (s *GORMStoreV2) ListAPIKeys(ctx context.Context) ([]*metadata.APIKey, error) {
	var models []APIKeyModel
	if err := s.db.WithContext(ctx).Order("created_at DESC").Find(&models).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list api keys")
	}
	out := make([]*metadata.APIKey, len(models))
	for i := range models {
		out[i] = apiKeyModelToMetadata(&models[i])
	}
	return out, nil
}

// DeleteAPIKey hard-deletes an API key by ID. Use SaveAPIKey with Revoked=true
// for audit-friendly revocation; this method is for explicit purges.
func (s *GORMStoreV2) DeleteAPIKey(ctx context.Context, id string) error {
	result := s.db.WithContext(ctx).Where("id = ?", id).Delete(&APIKeyModel{})
	if result.Error != nil {
		return errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to delete api key")
	}
	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, "api key not found")
	}
	return nil
}

// UpdateAPIKeyLastUsed updates only last_used_at. Cheap (single column UPDATE).
// Auth manager calls this asynchronously per-request; do not perform extra
// work here without measuring impact.
func (s *GORMStoreV2) UpdateAPIKeyLastUsed(ctx context.Context, id string, t time.Time) error {
	result := s.db.WithContext(ctx).
		Model(&APIKeyModel{}).
		Where("id = ?", id).
		Update("last_used_at", t)
	if result.Error != nil {
		return errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to update api key last used")
	}
	// Missing rows are not fatal: caller validated the key against an
	// in-memory snapshot that may have lagged a concurrent revoke.
	return nil
}

func apiKeyModelToMetadata(m *APIKeyModel) *metadata.APIKey {
	return &metadata.APIKey{
		ID:          m.ID,
		KeyHash:     m.KeyHash,
		Project:     m.Project,
		Role:        m.Role,
		Permissions: m.Permissions,
		CreatedAt:   m.CreatedAt,
		ExpiresAt:   m.ExpiresAt,
		LastUsedAt:  m.LastUsedAt,
		Revoked:     m.Revoked,
	}
}
