package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
	"github.com/stretchr/testify/require"
)

type trendingResponse struct {
	Packages []trendingPackage `json:"packages"`
	Total    int               `json:"total"`
}

func getTrending(t *testing.T, a *App, query string) trendingResponse {
	t.Helper()
	f := fiber.New()
	f.Get("/api/analytics/trending", a.handleAnalyticsTrendingPackages)
	resp, err := f.Test(httptest.NewRequest("GET", "/api/analytics/trending"+query, nil))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	var out trendingResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func seedDownloads(t *testing.T, store metadata.Store, registry, name, version string, n int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: registry, Name: name, Version: version, StorageKey: registry + "/" + name + "/" + version,
		Size: 1, CachedAt: now, LastAccessed: now,
	}))
	for i := 0; i < n; i++ {
		require.NoError(t, store.UpdateDownloadCount(ctx, registry, name, version))
	}
}

func TestTrendingServedFromPersistedDownloads(t *testing.T) {
	store, err := gormstore.NewV2(gormstore.Config{
		Driver: "sqlite", DSN: fmt.Sprintf("file:trend_%d?mode=memory&cache=shared", time.Now().UnixNano()),
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: "silent",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	seedDownloads(t, store, "npm", "left-pad", "1.3.0", 3)
	seedDownloads(t, store, "go", "github.com/google/uuid/@v/v1.6.0.zip", "v1.6.0", 2)
	seedDownloads(t, store, "go", "github.com/google/uuid/@v/v1.6.0.mod", "v1.6.0", 2)

	// A fresh engine is what a restarted server has: it must not decide the ranking.
	engine := analytics.NewEngine(analytics.Config{MaxEvents: 10, FlushInterval: time.Minute})
	t.Cleanup(engine.Close)

	got := getTrending(t, &App{metadata: store, analyticsEngine: engine}, "")
	require.Equal(t, 2, got.Total)
	require.Equal(t, "npm", got.Packages[0].Registry)
	require.Equal(t, "left-pad", got.Packages[0].Name)
	require.Equal(t, int64(3), got.Packages[0].RecentDownloads)
	require.Equal(t, int64(0), got.Packages[0].PreviousDownloads)
	require.Equal(t, "github.com/google/uuid", got.Packages[1].Name)
	require.Equal(t, int64(2), got.Packages[1].RecentDownloads)

	limited := getTrending(t, &App{metadata: store, analyticsEngine: engine}, "?limit=1")
	require.Len(t, limited.Packages, 1)
}

func TestTrendingFallsBackToEngineWithoutPersistedHistory(t *testing.T) {
	engine := analytics.NewEngine(analytics.Config{MaxEvents: 10, FlushInterval: time.Minute})
	t.Cleanup(engine.Close)
	engine.TrackDownload(analytics.PackageDownload{Registry: "npm", Name: "lodash", Version: "4", Timestamp: time.Now()})

	got := getTrending(t, &App{analyticsEngine: engine}, "")
	require.Equal(t, 1, got.Total)
	require.Equal(t, "lodash", got.Packages[0].Name)
}
