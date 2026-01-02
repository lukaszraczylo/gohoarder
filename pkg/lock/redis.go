package lock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

var (
	ErrLockNotAcquired = errors.New("lock not acquired")
	ErrLockNotHeld     = errors.New("lock not held by this instance")
	ErrInvalidTTL      = errors.New("invalid TTL: must be positive")
)

// Lock represents a distributed lock
type Lock struct {
	client *redis.Client
	key    string
	value  string
	ttl    time.Duration
}

// Manager manages distributed locks using Redis
type Manager struct {
	client *redis.Client
}

// Config holds Redis connection configuration
type Config struct {
	Addr     string
	Password string
	DB       int
}

// NewManager creates a new lock manager
func NewManager(cfg Config) (*Manager, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	log.Info().
		Str("addr", cfg.Addr).
		Int("db", cfg.DB).
		Msg("Connected to Redis for distributed locking")

	return &Manager{
		client: client,
	}, nil
}

// Acquire attempts to acquire a lock with the given key and TTL
// Returns a Lock instance if successful, or an error if the lock is already held
func (m *Manager) Acquire(ctx context.Context, key string, ttl time.Duration) (*Lock, error) {
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}

	// Generate unique value for this lock instance
	value, err := generateLockValue()
	if err != nil {
		return nil, err
	}

	// Try to acquire lock using SET NX (set if not exists)
	success, err := m.client.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		log.Error().
			Err(err).
			Str("key", key).
			Msg("Failed to acquire lock")
		return nil, err
	}

	if !success {
		log.Debug().
			Str("key", key).
			Msg("Lock already held by another instance")
		return nil, ErrLockNotAcquired
	}

	log.Debug().
		Str("key", key).
		Dur("ttl", ttl).
		Msg("Lock acquired successfully")

	return &Lock{
		client: m.client,
		key:    key,
		value:  value,
		ttl:    ttl,
	}, nil
}

// TryAcquire attempts to acquire a lock, retrying for the specified duration
// Returns a Lock instance if successful within the timeout, or an error
func (m *Manager) TryAcquire(ctx context.Context, key string, ttl, timeout time.Duration) (*Lock, error) {
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		lock, err := m.Acquire(ctx, key, ttl)
		if err == nil {
			return lock, nil
		}

		if err != ErrLockNotAcquired {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, ErrLockNotAcquired
			}
		}
	}
}

// Release releases the lock
// Returns an error if the lock is not held by this instance
func (l *Lock) Release(ctx context.Context) error {
	// Use Lua script to ensure atomic check-and-delete
	// Only delete if the value matches (ensures we own the lock)
	script := redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`)

	result, err := script.Run(ctx, l.client, []string{l.key}, l.value).Result()
	if err != nil {
		log.Error().
			Err(err).
			Str("key", l.key).
			Msg("Failed to release lock")
		return err
	}

	// Result of 0 means the lock was not deleted (not owned by us)
	if result.(int64) == 0 {
		log.Warn().
			Str("key", l.key).
			Msg("Attempted to release lock not held by this instance")
		return ErrLockNotHeld
	}

	log.Debug().
		Str("key", l.key).
		Msg("Lock released successfully")

	return nil
}

// Extend extends the lock TTL
// Returns an error if the lock is not held by this instance
func (l *Lock) Extend(ctx context.Context, additionalTTL time.Duration) error {
	// Use Lua script to ensure atomic check-and-extend
	script := redis.NewScript(`
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("expire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`)

	newTTL := l.ttl + additionalTTL
	result, err := script.Run(ctx, l.client, []string{l.key}, l.value, int(newTTL.Seconds())).Result()
	if err != nil {
		log.Error().
			Err(err).
			Str("key", l.key).
			Msg("Failed to extend lock")
		return err
	}

	if result.(int64) == 0 {
		log.Warn().
			Str("key", l.key).
			Msg("Attempted to extend lock not held by this instance")
		return ErrLockNotHeld
	}

	l.ttl = newTTL
	log.Debug().
		Str("key", l.key).
		Dur("new_ttl", newTTL).
		Msg("Lock TTL extended")

	return nil
}

// IsHeld checks if the lock is still held by this instance
func (l *Lock) IsHeld(ctx context.Context) bool {
	value, err := l.client.Get(ctx, l.key).Result()
	if err != nil {
		return false
	}
	return value == l.value
}

// Close closes the lock manager and its Redis connection
func (m *Manager) Close() error {
	return m.client.Close() // #nosec G104 -- Cleanup, error not critical
}

// generateLockValue generates a cryptographically random lock value
func generateLockValue() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// WithLock executes a function while holding a distributed lock
// The lock is automatically released when the function returns
func (m *Manager) WithLock(ctx context.Context, key string, ttl time.Duration, fn func(context.Context) error) error {
	lock, err := m.Acquire(ctx, key, ttl)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(context.Background()); err != nil {
			log.Error().
				Err(err).
				Str("key", key).
				Msg("Failed to release lock in defer")
		}
	}()

	return fn(ctx)
}

// WithRetryLock executes a function while holding a distributed lock
// It retries acquisition for the specified timeout duration
func (m *Manager) WithRetryLock(ctx context.Context, key string, ttl, timeout time.Duration, fn func(context.Context) error) error {
	lock, err := m.TryAcquire(ctx, key, ttl, timeout)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(context.Background()); err != nil {
			log.Error().
				Err(err).
				Str("key", key).
				Msg("Failed to release lock in defer")
		}
	}()

	return fn(ctx)
}
