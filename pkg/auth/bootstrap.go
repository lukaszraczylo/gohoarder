package auth

import (
	"context"
	stderrors "errors"
	"os"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// BootstrapAdminEnvVar is the env var consulted by BootstrapAdminFromEnv.
// Exported so callers and operators can reference a single source of truth.
const BootstrapAdminEnvVar = "GOHOARDER_BOOTSTRAP_ADMIN_KEY"

// bootstrapProject is the marker project assigned to the env-bootstrapped
// admin key. Callers can list keys filtered by this project to inventory
// bootstrap-origin credentials.
const bootstrapProject = "bootstrap"

// BootstrapAdminFromEnv creates an initial admin API key from the
// GOHOARDER_BOOTSTRAP_ADMIN_KEY environment variable when no admin key
// already exists in the store.
//
// Behaviour matrix:
//   - env unset/empty            -> no-op, nil
//   - store nil                  -> no-op, nil (caller must provide a store)
//   - store has any non-revoked
//     admin key                  -> log and return nil (idempotent)
//   - else                       -> bcrypt-hash env value, persist as admin
//
// The env var holds the RAW key the operator wants to use; we hash it with
// the configured bcrypt cost (default DefaultCost) before storing. The
// operator is expected to clear the env var after first successful boot.
func BootstrapAdminFromEnv(ctx context.Context, store metadata.MetadataStore, cfg Config) error {
	rawKey := os.Getenv(BootstrapAdminEnvVar)
	if rawKey == "" {
		return nil
	}
	if store == nil {
		log.Warn().Msg("Bootstrap admin key requested but no metadata store configured; skipping")
		return nil
	}

	cost := cfg.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	// Idempotency: if any non-revoked admin already exists, skip.
	existing, err := store.ListAPIKeys(ctx)
	if err != nil {
		if stderrors.Is(err, metadata.ErrNotImplemented) {
			log.Warn().Msg("Bootstrap admin: store does not implement API key persistence; skipping")
			return nil
		}
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "bootstrap admin: failed to list existing keys")
	}

	for _, k := range existing {
		if k == nil || k.Revoked {
			continue
		}
		if k.Role == storedRoleAdmin {
			log.Info().Msg("Bootstrap admin skipped — admin key already exists")
			return nil
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(rawKey), cost)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalServer, "bootstrap admin: failed to hash key")
	}

	now := time.Now()
	key := &metadata.APIKey{
		ID:        generateID(),
		KeyHash:   string(hashed),
		Project:   bootstrapProject,
		Role:      storedRoleAdmin,
		CreatedAt: now,
		Revoked:   false,
	}

	if err := store.SaveAPIKey(ctx, key); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "bootstrap admin: failed to save key")
	}

	// SECURITY: never log the raw key or its hash.
	log.Info().
		Str("key_id", key.ID).
		Str("project", bootstrapProject).
		Msg("Bootstrap admin created — delete " + BootstrapAdminEnvVar + " after first run")

	return nil
}
