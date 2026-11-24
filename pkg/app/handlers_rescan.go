package app

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/rs/zerolog/log"
)

type rescanRequest struct {
	Scope scanner.RescanScope `json:"scope"`
}

// jobContext is the context of work that outlives a request: it ends with the server.
func (a *App) jobContext() context.Context {
	if a.workerCtx != nil {
		return a.workerCtx
	}
	return context.Background()
}

func rescanStatusBody(a *App) fiber.Map {
	body := fiber.Map{"enabled": a.rescanWorker != nil, "running": false, "scope": "", "queued": 0, "done": 0, "failed": 0}
	if a.rescanWorker == nil {
		return body
	}
	st := a.rescanWorker.Status()
	body["running"], body["scope"] = st.Running, string(st.Scope)
	body["queued"], body["done"], body["failed"] = st.Queued, st.Done, st.Failed
	body["elapsed_seconds"] = int64(st.Elapsed.Seconds())
	// The rate so far predicts the rest; nothing is known before the first artifact finishes.
	if processed := st.Done + st.Failed; st.Running && processed > 0 {
		body["eta_seconds"] = int64(st.Elapsed.Seconds() * float64(st.Queued-processed) / float64(processed))
	}
	if !st.StartedAt.IsZero() {
		body["started_at"] = st.StartedAt.UTC().Format(time.RFC3339)
	}
	if !st.FinishedAt.IsZero() {
		body["finished_at"] = st.FinishedAt.UTC().Format(time.RFC3339)
	}
	return body
}

// handleRescanTrigger queues a rescan of cached artifacts and answers 202 with the queued count.
func (a *App) handleRescanTrigger(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	var req rescanRequest
	if err := c.Bind().Body(&req); err != nil || !req.Scope.Valid() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": `scope must be "vulnerable" or "all"`})
	}
	if a.rescanWorker == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": scanner.ErrRescanDisabled.Error()})
	}

	queued, err := a.rescanWorker.RescanNow(a.jobContext(), req.Scope)
	switch {
	case errors.Is(err, scanner.ErrRescanRunning):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error(), "status": rescanStatusBody(a)})
	case errors.Is(err, scanner.ErrRescanDisabled):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	case err != nil:
		log.Error().Err(err).Msg("Failed to queue rescan")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to queue rescan"})
	}

	log.Info().Str("scope", string(req.Scope)).Int("queued", queued).Msg("Rescan queued via API")
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"queued": queued, "scope": req.Scope})
}

type rescanScopeEstimate struct {
	// Seconds is null until the store has recorded a scan duration.
	Seconds   *int64 `json:"seconds"`
	Artifacts int    `json:"artifacts"`
}

// handleRescanEstimate sizes each scope from the artifact counts, the average of recent scan
// durations and the configured concurrency.
func (a *App) handleRescanEstimate(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	if a.rescanWorker == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": scanner.ErrRescanDisabled.Error()})
	}
	est, err := a.rescanWorker.Estimate(a.jobContext())
	if err != nil {
		log.Error().Err(err).Msg("Failed to estimate rescan")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to estimate rescan"})
	}
	sized := func(artifacts int) rescanScopeEstimate {
		out := rescanScopeEstimate{Artifacts: artifacts}
		if est.AvgScan > 0 {
			secs := int64(math.Ceil(est.AvgScan.Seconds() * float64(artifacts) / float64(max(est.Concurrency, 1))))
			out.Seconds = &secs
		}
		return out
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"vulnerable":       sized(est.Vulnerable),
		"all":              sized(est.All),
		"avg_scan_seconds": est.AvgScan.Seconds(),
		"concurrency":      est.Concurrency,
	})
}

// handleRescanStatus reports the progress of the latest admin-triggered rescan.
func (a *App) handleRescanStatus(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	return c.Status(fiber.StatusOK).JSON(rescanStatusBody(a))
}
