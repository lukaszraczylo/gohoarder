package gormstore

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

const trendingWindow = 7 * 24 * time.Hour

type trendingKey struct{ registry, name string }

type trendingRow struct {
	Registry string
	Name     string
	Version  string
	Count    int64
}

// GetTrendingPackages ranks packages by downloads in the last 7 days, with the 7 days before
// for the change. Downloads sit in raw events (current hour), hourly rows (kept 7 days) and
// daily rollups (older), the same layering GetTimeSeriesStats merges. The previous window ends
// exactly where the recent one starts: whole days come from the rollups, and the day that
// holds the boundary is its rollup minus the hourly rows after the boundary.
func (s *GORMStoreV2) GetTrendingPackages(ctx context.Context, limit int) ([]*metadata.TrendingPackage, error) {
	now := s.clock().UTC()
	since := now.Add(-trendingWindow).Truncate(time.Hour)
	boundaryDay := since.Truncate(24 * time.Hour)
	// Whole days only: pick the count that keeps the previous window closest to 7 days.
	fullDays := 7
	if since.Sub(boundaryDay) >= 12*time.Hour {
		fullDays = 6
	}
	// The 12h shift keeps midnight rows on the right side whether the driver stores a date or a timestamp.
	shift := 12 * time.Hour
	fullFrom, fullTo := boundaryDay.AddDate(0, 0, -fullDays).Add(-shift), boundaryDay.Add(-shift)

	hourly, err := s.packageDownloads(ctx, "download_stats_hourly s", "SUM(s.download_count)", "s.time_bucket >= ?", since)
	if err != nil {
		return nil, err
	}
	events, err := s.packageDownloads(ctx, "download_events s", "COUNT(*)", "s.downloaded_at >= ?", since)
	if err != nil {
		return nil, err
	}
	daily, err := s.packageDownloads(ctx, "download_stats_daily s", "SUM(s.download_count)", "s.time_bucket >= ? AND s.time_bucket < ?", fullFrom, fullTo)
	if err != nil {
		return nil, err
	}
	partialDay, err := s.packageDownloads(ctx, "download_stats_daily s", "SUM(s.download_count)", "s.time_bucket >= ? AND s.time_bucket < ?", fullTo, boundaryDay.Add(shift))
	if err != nil {
		return nil, err
	}
	afterBoundary, err := s.packageDownloads(ctx, "download_stats_hourly s", "SUM(s.download_count)", "s.time_bucket >= ? AND s.time_bucket < ?", since, boundaryDay.Add(24*time.Hour))
	if err != nil {
		return nil, err
	}
	// Hourly rows trail the rollup, so the difference can dip below zero.
	after := make(map[trendingRow]int64, len(afterBoundary))
	for _, r := range afterBoundary {
		after[trendingRow{Registry: r.Registry, Name: r.Name, Version: r.Version}] += r.Count
	}
	for _, r := range partialDay {
		left := r.Count - after[trendingRow{Registry: r.Registry, Name: r.Name, Version: r.Version}]
		if left > 0 {
			daily = append(daily, trendingRow{Registry: r.Registry, Name: r.Name, Version: r.Version, Count: left})
		}
	}

	totals := make(map[trendingKey]*metadata.TrendingPackage)
	add := func(rows []trendingRow, recent bool) {
		for _, r := range rows {
			if metadata.IsMetadataEntry(r.Registry, r.Name, r.Version) {
				continue
			}
			name := r.Name
			if r.Registry == metadata.GoRegistry {
				name, _, _ = strings.Cut(name, "/@v/")
			}
			key := trendingKey{r.Registry, name}
			pkg := totals[key]
			if pkg == nil {
				pkg = &metadata.TrendingPackage{Registry: r.Registry, Name: name}
				totals[key] = pkg
			}
			if recent {
				pkg.Recent += r.Count
			} else {
				pkg.Previous += r.Count
			}
		}
	}
	add(hourly, true)
	add(events, true)
	add(daily, false)

	ranked := make([]*metadata.TrendingPackage, 0, len(totals))
	for _, pkg := range totals {
		if pkg.Recent > 0 {
			ranked = append(ranked, pkg)
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Recent != ranked[j].Recent {
			return ranked[i].Recent > ranked[j].Recent
		}
		if ranked[i].Registry != ranked[j].Registry {
			return ranked[i].Registry < ranked[j].Registry
		}
		return ranked[i].Name < ranked[j].Name
	})
	if limit > 0 && limit < len(ranked) {
		ranked = ranked[:limit]
	}
	return ranked, nil
}

// packageDownloads sums one download table per package row; table carries the alias "s".
func (s *GORMStoreV2) packageDownloads(ctx context.Context, table, sum, cond string, args ...interface{}) ([]trendingRow, error) {
	var rows []trendingRow
	err := s.db.WithContext(ctx).
		Table(table).
		Select("r.name AS registry, p.name AS name, p.version AS version, "+sum+" AS count").
		Joins("JOIN packages p ON p.id = s.package_id").
		Joins("JOIN registries r ON r.id = p.registry_id").
		Where("s.package_id IS NOT NULL").
		Where(cond, args...).
		Group("r.name, p.name, p.version").
		Scan(&rows).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read trending downloads")
	}
	return rows, nil
}
