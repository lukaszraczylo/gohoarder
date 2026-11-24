package app

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/rs/zerolog/log"
)

// layoutRows is the value of ?layout= that selects one flat page of package rows.
const layoutRows = "rows"

// Sort keys of the rows layout.
const (
	rowSortName         = "name"
	rowSortVersion      = "version"
	rowSortRegistry     = "registry"
	rowSortSize         = "size"
	rowSortDownloads    = "downloads"
	rowSortLastAccessed = "last_accessed"
	rowSortLastScanned  = "last_scanned"
	rowSortRisk         = "risk"
)

// decisionChunk bounds the id list of one scan summary query.
const decisionChunk = 500

type rowParams struct {
	registry   string
	query      string
	verdict    string
	sortBy     string
	severities []string
	page       int
	pageSize   int
	desc       bool
}

// parseRowParams reads registry, q, verdict, severity, sort, order, page and page_size.
func parseRowParams(c fiber.Ctx) (rowParams, error) {
	p := rowParams{
		registry: c.Query("registry"),
		query:    c.Query("q"),
		sortBy:   rowSortName,
		page:     max(fiber.Query[int](c, "page", 1), 1),
		pageSize: fiber.Query[int](c, "page_size", defaultPageSize),
	}
	if p.pageSize < 1 {
		p.pageSize = defaultPageSize
	}
	p.pageSize = min(p.pageSize, maxPageSize)

	switch v := c.Query("verdict"); v {
	case "":
	case VerdictCleared, VerdictHeld, VerdictBypassed, VerdictPending:
		p.verdict = v
	default:
		return p, fiber.NewError(fiber.StatusBadRequest, "invalid verdict, must be one of: cleared, held, bypassed, pending")
	}
	switch s := c.Query("sort"); s {
	case "":
	case rowSortName, rowSortVersion, rowSortRegistry, rowSortSize, rowSortDownloads, rowSortLastAccessed, rowSortLastScanned, rowSortRisk:
		p.sortBy = s
	default:
		return p, fiber.NewError(fiber.StatusBadRequest, "invalid sort key")
	}
	switch c.Query("order") {
	case "desc":
		p.desc = true
	case "asc", "":
	default:
		return p, fiber.NewError(fiber.StatusBadRequest, "invalid order, must be asc or desc")
	}
	sev, err := parseSeverities(c.Query("severity"))
	if err != nil {
		return p, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	p.severities = sev
	return p, nil
}

// packageRow is a cached package with the verdict the policy gives it now.
type packageRow struct {
	pkg       *metadata.Package
	verdict   string
	scannedAt time.Time
	dec       scanner.ScanDecision
	scanned   bool
}

func (r packageRow) severityCount(level string) int {
	s := r.dec.Summary
	switch level {
	case metadata.SeverityCritical:
		return s.Critical
	case metadata.SeverityHigh:
		return s.High
	case metadata.SeverityModerate:
		return s.Moderate
	default:
		return s.Low
	}
}

// loadDecisions judges every scanned row in bounded chunks.
func (a *App) loadDecisions(ctx context.Context, pkgs []*metadata.Package) (map[string]scanner.ScanDecision, error) {
	var ids []string
	for _, p := range pkgs {
		if p.SecurityScanned {
			ids = append(ids, p.ID)
		}
	}
	out := make(map[string]scanner.ScanDecision, len(ids))
	for chunk := range slices.Chunk(ids, decisionChunk) {
		list, err := a.scanDecisions(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for _, d := range list {
			out[d.Summary.PackageID] = d
		}
	}
	return out, nil
}

func rowOf(pkg *metadata.Package, decisions map[string]scanner.ScanDecision) packageRow {
	row := packageRow{pkg: pkg, verdict: VerdictPending}
	if d, ok := decisions[pkg.ID]; ok && pkg.SecurityScanned && d.Summary.HasScan {
		row.dec, row.scanned, row.verdict, row.scannedAt = d, true, verdictOf(d), d.Summary.ScannedAt
	}
	return row
}

func compareRows(sortBy string, a, b packageRow) int {
	switch sortBy {
	case rowSortVersion:
		return cmp.Compare(strings.ToLower(displayVersionOf(a.pkg)), strings.ToLower(displayVersionOf(b.pkg)))
	case rowSortRegistry:
		return cmp.Compare(a.pkg.Registry, b.pkg.Registry)
	case rowSortSize:
		return cmp.Compare(a.pkg.Size, b.pkg.Size)
	case rowSortDownloads:
		return cmp.Compare(a.pkg.DownloadCount, b.pkg.DownloadCount)
	case rowSortLastAccessed:
		return a.pkg.LastAccessed.Compare(b.pkg.LastAccessed)
	case rowSortLastScanned:
		return a.scannedAt.Compare(b.scannedAt)
	case rowSortRisk:
		return compareRisk(a, b)
	default:
		return cmp.Compare(strings.ToLower(a.pkg.Name), strings.ToLower(b.pkg.Name))
	}
}

// compareRisk orders by critical, then high, then moderate, then low findings.
func compareRisk(a, b packageRow) int {
	for _, level := range metadata.Severities {
		if c := cmp.Compare(a.severityCount(level), b.severityCount(level)); c != 0 {
			return c
		}
	}
	return 0
}

func displayVersionOf(p *metadata.Package) string {
	if p.ReleaseVersion != "" {
		return p.ReleaseVersion
	}
	return p.Version
}

func sortRows(rows []packageRow, p rowParams) {
	slices.SortStableFunc(rows, func(a, b packageRow) int {
		c := compareRows(p.sortBy, a, b)
		if p.desc {
			c = -c
		}
		if c != 0 {
			return c
		}
		return cmp.Or(
			cmp.Compare(strings.ToLower(a.pkg.Name), strings.ToLower(b.pkg.Name)),
			cmp.Compare(a.pkg.Registry, b.pkg.Registry),
			cmp.Compare(a.pkg.Version, b.pkg.Version),
			cmp.Compare(a.pkg.ID, b.pkg.ID),
		)
	})
}

// rowCounts summarise the rows that match the registry and query, before the verdict and severity filters.
type rowCounts struct {
	Verdicts         map[string]int `json:"verdicts"`
	SeverityPackages map[string]int `json:"severity_packages"`
	SeverityFindings map[string]int `json:"severity_findings"`
	VulnerableAllow  int            `json:"vulnerable_allowed"`
}

func countRows(rows []packageRow) rowCounts {
	c := rowCounts{
		Verdicts:         map[string]int{VerdictCleared: 0, VerdictHeld: 0, VerdictBypassed: 0, VerdictPending: 0},
		SeverityPackages: map[string]int{},
		SeverityFindings: map[string]int{},
	}
	for _, level := range metadata.Severities {
		c.SeverityPackages[level], c.SeverityFindings[level] = 0, 0
	}
	for _, r := range rows {
		c.Verdicts[r.verdict]++
		if !r.scanned {
			continue
		}
		if r.verdict == VerdictCleared && r.dec.Summary.Total > 0 {
			c.VulnerableAllow++
		}
		for _, level := range metadata.Severities {
			if n := r.severityCount(level); n > 0 {
				c.SeverityPackages[level]++
				c.SeverityFindings[level] += n
			}
		}
	}
	return c
}

func (p rowParams) keeps(r packageRow) bool {
	if p.verdict != "" && r.verdict != p.verdict {
		return false
	}
	if len(p.severities) == 0 {
		return true
	}
	return slices.ContainsFunc(p.severities, func(level string) bool { return r.severityCount(level) > 0 })
}

// handleListPackageRows serves one sorted, filtered page of package rows.
//
// The store filters by registry and query in SQL and returns the matching rows.
// The verdict depends on the scan policy and the live bypasses, so it is computed in
// memory for those rows, in chunks of decisionChunk ids. Sorting and paging then run on
// the filtered rows. The cost is one pass over the registry/query matches, never the page.
func (a *App) handleListPackageRows(c fiber.Ctx) error {
	ctx := c.Context()
	p, err := parseRowParams(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	page, err := a.metadata.ListPackageGroups(ctx, metadata.GroupListOptions{Registry: p.registry, Query: p.query, SortBy: metadata.GroupSortName})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list packages"})
	}

	securityOn := a.config.Security.Enabled
	decisions := map[string]scanner.ScanDecision{}
	if securityOn {
		if decisions, err = a.loadDecisions(ctx, page.Packages); err != nil {
			log.Error().Err(err).Msg("Failed to load scan summaries")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list packages"})
		}
	}
	all := make([]packageRow, len(page.Packages))
	for i, pkg := range page.Packages {
		all[i] = rowOf(pkg, decisions)
	}
	counts := countRows(all)

	matched := all
	if securityOn {
		matched = slices.DeleteFunc(slices.Clone(all), func(r packageRow) bool { return !p.keeps(r) })
	} else if p.verdict != "" || len(p.severities) > 0 {
		matched = nil
	}
	sortRows(matched, p)

	start := min((p.page-1)*p.pageSize, len(matched))
	end := min(start+p.pageSize, len(matched))
	items := make([]map[string]interface{}, 0, end-start)
	for _, r := range matched[start:end] {
		item := packageSummary(r.pkg)
		if securityOn {
			item["vulnerabilities"] = vulnerabilityInfo(r.pkg, decisions)
		}
		items = append(items, item)
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"packages":  items,
		"total":     len(matched),
		"page":      p.page,
		"page_size": p.pageSize,
		"counts":    counts,
	})
}
