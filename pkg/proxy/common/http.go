package common

import (
	"context"
	"io"
	"net/http"

	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/rs/zerolog/log"
)

// FetchFromUpstream is a common helper to fetch content from upstream with caching
// This encapsulates the common pattern of: cache.Get -> network.Get -> error handling
func FetchFromUpstream(
	ctx context.Context,
	cacheManager *cache.Manager,
	client *network.Client,
	registry, name, version, upstreamURL string,
) (*cache.CacheEntry, error) {
	entry, err := cacheManager.Get(ctx, registry, name, version, func(ctx context.Context) (io.ReadCloser, string, error) {
		body, statusCode, err := client.Get(ctx, upstreamURL, nil)
		if err != nil {
			return nil, "", err
		}
		if err := CheckUpstreamStatus(statusCode, body); err != nil {
			return nil, "", err
		}
		return body, upstreamURL, nil
	})

	if err != nil {
		log.Error().
			Err(err).
			Str("url", upstreamURL).
			Str("registry", registry).
			Str("name", name).
			Str("version", version).
			Msg("Failed to fetch package from upstream")
		return nil, err
	}

	return entry, nil
}

// WriteResponse writes the cache entry data to the HTTP response writer
// Sets appropriate content type and handles errors
func WriteResponse(w http.ResponseWriter, entry *cache.CacheEntry, contentType string) error {
	defer entry.Data.Close() // #nosec G104 -- Cleanup, error not critical

	w.Header().Set("Content-Type", contentType)
	if _, err := io.Copy(w, entry.Data); err != nil {
		log.Error().Err(err).Msg("Failed to write response")
		return err
	}

	return nil
}
