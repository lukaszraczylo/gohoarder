package app

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/internal/version"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/ghsa"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/govulncheck"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/grype"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/npmaudit"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/osv"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/pipaudit"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/trivy"
)

type scannerSwitch struct {
	name    string
	enabled bool
}

// scannerSwitches lists every scanner the manager can register, in display order.
func scannerSwitches(s config.ScannersConfig) []scannerSwitch {
	return []scannerSwitch{
		{trivy.ScannerName, s.Trivy.Enabled},
		{grype.ScannerName, s.Grype.Enabled},
		{osv.ScannerName, s.OSV.Enabled},
		{govulncheck.ScannerName, s.Govulncheck.Enabled},
		{npmaudit.ScannerName, s.NpmAudit.Enabled},
		{pipaudit.ScannerName, s.PipAudit.Enabled},
		{ghsa.ScannerName, s.GHSA.Enabled},
	}
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }

// systemScanners joins the configured scanners with their cached health; disabled scanners report no health.
func (a *App) systemScanners(ctx context.Context) []fiber.Map {
	sec := a.config.Security
	health := map[string]fiber.Map{}
	if sec.Enabled && a.scanManager != nil {
		for _, st := range a.scanManager.Statuses(ctx) {
			health[st.Name] = fiber.Map{"healthy": st.Healthy, "version": st.Version}
		}
	}
	out := make([]fiber.Map, 0, 7)
	for _, sw := range scannerSwitches(sec.Scanners) {
		entry := fiber.Map{"name": sw.name, "enabled": sw.enabled && sec.Enabled, "healthy": nil, "version": ""}
		if h, ok := health[sw.name]; ok {
			entry["healthy"], entry["version"] = h["healthy"], h["version"]
		}
		out = append(out, entry)
	}
	return out
}

// handleSystem reports the effective policy and settings; it exposes no credentials, DSNs or paths.
// Durations are whole seconds; a negative threshold means unlimited.
func (a *App) handleSystem(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	if c.Method() != "GET" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}

	sec := a.config.Security
	scanWait := sec.ScanWaitTimeout
	if scanWait == 0 {
		scanWait = cache.DefaultScanWaitTimeout
	}
	concurrency := max(sec.RescanConcurrency, 1)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"version": version.Version,
		"security": fiber.Map{
			"enabled":           sec.Enabled,
			"fail_closed":       sec.FailClosed,
			"scan_on_download":  sec.ScanOnDownload,
			"block_on_severity": sec.BlockOnSeverity,
			"block_thresholds": fiber.Map{
				"critical": sec.BlockThresholds.Critical,
				"high":     sec.BlockThresholds.High,
				"moderate": sec.BlockThresholds.Medium,
				"low":      sec.BlockThresholds.Low,
			},
			"scan_wait_timeout": seconds(scanWait),
			"scanners":          a.systemScanners(c.Context()),
			"rescan": fiber.Map{
				"interval":      seconds(sec.RescanInterval),
				"active_window": seconds(sec.RescanActiveWindow),
				"concurrency":   concurrency,
				"on_access":     sec.RescanOnAccess,
			},
		},
		"cache": fiber.Map{
			"max_size":    a.config.Cache.MaxSizeBytes,
			"idle_ttl":    seconds(a.config.Cache.IdleTTL),
			"default_ttl": seconds(a.config.Cache.DefaultTTL),
		},
		"prewarming": fiber.Map{
			"enabled":      a.prewarmWorker != nil && a.config.Prewarming.Enabled,
			"interval":     seconds(a.config.Prewarming.Interval),
			"top_packages": a.config.Prewarming.TopPackages,
		},
	})
}
