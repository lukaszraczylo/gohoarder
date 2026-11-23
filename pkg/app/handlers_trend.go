package app

import (
	"context"
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// trendPeriods maps the period query value of /api/stats/trend to days of history.
var trendPeriods = map[string]int{"30day": 30, "90day": 90, "1year": 365}

const defaultTrendPeriod = "30day"

// handleStatsTrend returns one snapshot per day for the period, oldest first.
// Vulnerability fields are null for days before vulnerability history starts.
func (a *App) handleStatsTrend(c fiber.Ctx) error {
	period := c.Query("period", defaultTrendPeriod)
	days, ok := trendPeriods[period]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid period, must be one of: 30day, 90day, 1year",
		})
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	from := today.AddDate(0, 0, -(days - 1))
	points, err := a.metadata.GetStatsTrend(c.Context(), from)
	if err != nil && !errors.Is(err, metadata.ErrNotImplemented) {
		log.Error().Err(err).Str("period", period).Msg("Failed to get stats trend")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get stats trend"})
	}
	if points == nil {
		points = []*metadata.StatsSnapshot{}
	}

	var vulnStart *string
	for _, p := range points {
		if p.VulnerablePackages != nil {
			vulnStart = &p.Date
			break
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"period":                      period,
		"from":                        from.Format(metadata.StatsSnapshotDateLayout),
		"to":                          today.Format(metadata.StatsSnapshotDateLayout),
		"vulnerability_history_start": vulnStart,
		"points":                      points,
	})
}

// countBlocked counts scanned artifacts the blocking policy refuses.
func (a *App) countBlocked(ctx context.Context) (int64, error) {
	if !a.config.Security.Enabled || a.scanManager == nil {
		return 0, nil
	}
	decisions, err := a.scanManager.ScanDecisions(ctx, nil)
	if err != nil {
		return 0, err
	}
	var blocked int64
	for _, d := range decisions {
		if d.Blocked && !metadata.IsMetadataVersion(d.Summary.Version) {
			blocked++
		}
	}
	return blocked, nil
}

// blockedCounterSetter is implemented by stores that snapshot blocked packages.
type blockedCounterSetter interface {
	SetBlockedCounter(func(context.Context) (int64, error))
}
