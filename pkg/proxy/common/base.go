package common

import (
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
)

// BaseHandler provides common functionality for all proxy handlers
type BaseHandler struct {
	Cache    *cache.Manager
	Client   *network.Client
	Upstream string
	Registry string
}

// Config holds common proxy configuration
type Config struct {
	Upstream string // Upstream registry URL (e.g., registry.npmjs.org)
}

// GetRegistry returns the registry type
func (h *BaseHandler) GetRegistry() string {
	return h.Registry
}

// NewBaseHandler creates a new base handler with common fields
func NewBaseHandler(cache *cache.Manager, client *network.Client, registry, upstream string) *BaseHandler {
	return &BaseHandler{
		Cache:    cache,
		Client:   client,
		Upstream: upstream,
		Registry: registry,
	}
}
