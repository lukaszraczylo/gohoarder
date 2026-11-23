package gormstore

import (
	"context"
	"sort"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	day           = 24 * time.Hour
	snapshotBatch = 500
)

// artifactPackages limits a query on packages to cache artifacts: no metadata
// pages and no Go .mod/.info files, as GetStats counts them.
func artifactPackages(db *gorm.DB) *gorm.DB {
	return db.Where("version NOT IN ?", metadata.MetadataVersions).
		Where("name NOT LIKE ?", "%.mod").Where("name NOT LIKE ?", "%.info")
}

func dayString(t time.Time) string { return t.UTC().Format(metadata.StatsSnapshotDateLayout) }

func ptr(v int64) *int64 { return &v }

// liveSnapshot reads the current cache state in one statement. blocked may be nil.
func liveSnapshot(ctx context.Context, db *gorm.DB, at time.Time, blocked *int64) (*StatsSnapshotModel, error) {
	var r struct {
		Total      int64
		Size       int64
		Vulnerable int64
		Critical   int64
		High       int64
		Moderate   int64
		Low        int64
	}
	// A package counts under every severity its latest scan holds, as the severity filter selects it.
	scanned := func(col string) string {
		return "COALESCE(SUM(CASE WHEN security_scanned = ? AND id IN (" + latestScanWith(col+" > 0") + ") THEN 1 ELSE 0 END), 0)"
	}
	err := artifactPackages(db.WithContext(ctx).Model(&PackageModel{})).Select(`
		COUNT(*) AS total,
		COALESCE(SUM(size), 0) AS size,
		`+scanned("vuln_count")+` AS vulnerable,
		`+scanned(severityColumns[metadata.SeverityCritical])+` AS critical,
		`+scanned(severityColumns[metadata.SeverityHigh])+` AS high,
		`+scanned(severityColumns[metadata.SeverityModerate])+` AS moderate,
		`+scanned(severityColumns[metadata.SeverityLow])+` AS low`, true, true, true, true, true).
		Scan(&r).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read stats for snapshot")
	}
	return &StatsSnapshotModel{
		Day:                dayString(at),
		TotalPackages:      r.Total,
		TotalSize:          r.Size,
		VulnerablePackages: ptr(r.Vulnerable),
		Critical:           ptr(r.Critical),
		High:               ptr(r.High),
		Moderate:           ptr(r.Moderate),
		Low:                ptr(r.Low),
		Blocked:            blocked,
	}, nil
}

// snapshotColumns are overwritten when a day's snapshot is written again.
var snapshotColumns = []string{
	"total_packages", "total_size", "vulnerable_packages", "critical", "high", "moderate", "low", "blocked", "updated_at",
}

// upsertSnapshot writes the day's row, replacing an earlier write of the same day.
// A nil blocked keeps the stored value so a run without a blocking policy never erases it.
func upsertSnapshot(ctx context.Context, db *gorm.DB, snap *StatsSnapshotModel) error {
	cols := snapshotColumns
	if snap.Blocked == nil {
		cols = make([]string, 0, len(snapshotColumns))
		for _, c := range snapshotColumns {
			if c != "blocked" {
				cols = append(cols, c)
			}
		}
	}
	err := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "day"}},
		DoUpdates: clause.AssignmentColumns(cols),
	}).Create(snap).Error
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save stats snapshot")
	}
	return nil
}

// SnapshotStats records today's (UTC) cache state. Running it again the same
// day overwrites that day's row, so the last run of a day is its closing state.
func (w *AggregationWorker) SnapshotStats(ctx context.Context) error {
	now := w.clock()
	var blocked *int64
	if count := w.blockedCounter(); count != nil {
		n, err := count(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to count blocked packages for the stats snapshot")
		} else {
			blocked = ptr(n)
		}
	}
	snap, err := liveSnapshot(ctx, w.db, now, blocked)
	if err != nil {
		return err
	}
	if err := upsertSnapshot(ctx, w.db, snap); err != nil {
		return err
	}
	log.Info().Str("day", snap.Day).Int64("packages", snap.TotalPackages).Msg("Recorded stats snapshot")
	return nil
}

// SetBlockedCounter sets how the snapshot counts blocked packages, which needs the scan policy the store lacks.
func (w *AggregationWorker) SetBlockedCounter(count func(context.Context) (int64, error)) {
	w.mu.Lock()
	w.blocked = count
	w.mu.Unlock()
}

func (w *AggregationWorker) blockedCounter() func(context.Context) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.blocked
}

// SetBlockedCounter sets how daily snapshots count blocked packages.
func (s *GORMStoreV2) SetBlockedCounter(count func(context.Context) (int64, error)) {
	if s.aggregationWorker != nil {
		s.aggregationWorker.SetBlockedCounter(count)
	}
}

// GetStatsTrend returns the daily snapshots from the UTC day of since, oldest first, in one statement.
func (s *GORMStoreV2) GetStatsTrend(ctx context.Context, since time.Time) ([]*metadata.StatsSnapshot, error) {
	var rows []StatsSnapshotModel
	if err := s.db.WithContext(ctx).Where("day >= ?", dayString(since)).Order("day").Find(&rows).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read stats snapshots")
	}
	out := make([]*metadata.StatsSnapshot, len(rows))
	for i, r := range rows {
		out[i] = &metadata.StatsSnapshot{
			Date:               r.Day,
			TotalPackages:      r.TotalPackages,
			TotalSize:          r.TotalSize,
			VulnerablePackages: r.VulnerablePackages,
			Critical:           r.Critical,
			High:               r.High,
			Moderate:           r.Moderate,
			Low:                r.Low,
			Blocked:            r.Blocked,
		}
	}
	return out, nil
}

// dayState is one package's contribution to a day's totals.
type dayState struct {
	size, vulnerable, critical, high, moderate, low int64
	alive                                           int64
}

func (a dayState) minus(b dayState) dayState {
	return dayState{
		alive: a.alive - b.alive, size: a.size - b.size, vulnerable: a.vulnerable - b.vulnerable,
		critical: a.critical - b.critical, high: a.high - b.high, moderate: a.moderate - b.moderate, low: a.low - b.low,
	}
}

func (a *dayState) add(b dayState) {
	a.alive += b.alive
	a.size += b.size
	a.vulnerable += b.vulnerable
	a.critical += b.critical
	a.high += b.high
	a.moderate += b.moderate
	a.low += b.low
}

// backfillScan is one scan result reduced to what the history needs.
type backfillScan struct {
	at                                         time.Time
	vulns, critical, high, moderate, lowCounts int
	id                                         int64
}

// backfillPackage is one package's lifetime: alive from cachedAt up to deletedAt.
type backfillPackage struct {
	cachedAt  time.Time
	deletedAt *time.Time
	size      int64
}

// stateAtDayEnd is the package's contribution at the end of the UTC day whose
// midnight-after is end. withScans is false for days before any scan exists.
func (p backfillPackage) stateAtDayEnd(end time.Time, scans []backfillScan, withScans bool) dayState {
	if !p.cachedAt.Before(end) || (p.deletedAt != nil && p.deletedAt.Before(end)) {
		return dayState{}
	}
	st := dayState{alive: 1, size: p.size}
	if !withScans {
		return st
	}
	// scans is sorted by (at, id); the last one before end is the latest.
	i := sort.Search(len(scans), func(i int) bool { return !scans[i].at.Before(end) })
	if i == 0 {
		return st
	}
	sc := scans[i-1]
	if sc.vulns > 0 {
		st.vulnerable = 1
	}
	// Every severity the scan holds counts, as in liveSnapshot.
	if sc.critical > 0 {
		st.critical = 1
	}
	if sc.high > 0 {
		st.high = 1
	}
	if sc.moderate > 0 {
		st.moderate = 1
	}
	if sc.lowCounts > 0 {
		st.low = 1
	}
	return st
}

// BackfillStatsSnapshots writes one snapshot per past UTC day, from the first
// package to the day before today, when no snapshot of a past day exists yet. Package counts
// come from cached_at and deleted_at. Vulnerability counts come from the
// append-only scan results and start at the first scan; earlier days leave
// them nil, as blocked is always nil (the policy at the time is not stored).
// It returns the number of days written.
func BackfillStatsSnapshots(ctx context.Context, db *gorm.DB, now time.Time) (int, error) {
	today := now.UTC().Truncate(day)
	var existing int64
	if err := db.WithContext(ctx).Model(&StatsSnapshotModel{}).Where("day < ?", dayString(today)).Count(&existing).Error; err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to count stats snapshots")
	}
	if existing > 0 {
		return 0, nil
	}

	pkgs, err := loadBackfillPackages(ctx, db)
	if err != nil {
		return 0, err
	}
	if len(pkgs) == 0 {
		return 0, nil
	}
	scans, firstScan, err := loadBackfillScans(ctx, db, pkgs)
	if err != nil {
		return 0, err
	}

	deltas := map[int64]dayState{}
	first := today
	for id, p := range pkgs {
		if d := p.cachedAt.UTC().Truncate(day); d.Before(first) {
			first = d
		}
		prev := dayState{}
		for _, d := range candidateDays(p, scans[id], today) {
			cur := p.stateAtDayEnd(d.Add(day), scans[id], !firstScan.IsZero() && !d.Before(firstScan))
			if delta := cur.minus(prev); delta != (dayState{}) {
				acc := deltas[d.Unix()]
				acc.add(delta)
				deltas[d.Unix()] = acc
			}
			prev = cur
		}
	}

	var rows []StatsSnapshotModel
	var total dayState
	for d := first; d.Before(today); d = d.Add(day) {
		total.add(deltas[d.Unix()])
		row := StatsSnapshotModel{Day: dayString(d), TotalPackages: total.alive, TotalSize: total.size}
		if !firstScan.IsZero() && !d.Before(firstScan) {
			row.VulnerablePackages, row.Critical, row.High = ptr(total.vulnerable), ptr(total.critical), ptr(total.high)
			row.Moderate, row.Low = ptr(total.moderate), ptr(total.low)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	err = db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(rows, snapshotBatch).Error
	if err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to backfill stats snapshots")
	}
	return len(rows), nil
}

// candidateDays lists, sorted, the days before today on which a package's
// end-of-day state can change: when it was cached, deleted or scanned.
func candidateDays(p backfillPackage, scans []backfillScan, today time.Time) []time.Time {
	set := map[int64]struct{}{}
	mark := func(t time.Time) {
		if d := t.UTC().Truncate(day); d.Before(today) {
			set[d.Unix()] = struct{}{}
		}
	}
	mark(p.cachedAt)
	if p.deletedAt != nil {
		mark(*p.deletedAt)
	}
	for _, s := range scans {
		mark(s.at)
	}
	days := make([]time.Time, 0, len(set))
	for unix := range set {
		days = append(days, time.Unix(unix, 0).UTC())
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Before(days[j]) })
	return days
}

func loadBackfillPackages(ctx context.Context, db *gorm.DB) (map[int64]backfillPackage, error) {
	var rows []struct {
		CachedAt  time.Time
		DeletedAt *time.Time
		ID        int64
		Size      int64
	}
	err := artifactPackages(db.WithContext(ctx).Unscoped().Model(&PackageModel{})).
		Select("id, cached_at, deleted_at, size").Scan(&rows).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read packages for backfill")
	}
	pkgs := make(map[int64]backfillPackage, len(rows))
	for _, r := range rows {
		pkgs[r.ID] = backfillPackage{cachedAt: r.CachedAt, deletedAt: r.DeletedAt, size: r.Size}
	}
	return pkgs, nil
}

// loadBackfillScans groups the scan results of the given packages and returns
// the UTC day of the first scan (zero when there is none).
func loadBackfillScans(ctx context.Context, db *gorm.DB, pkgs map[int64]backfillPackage) (map[int64][]backfillScan, time.Time, error) {
	var rows []struct {
		ScannedAt     time.Time
		ID            int64
		PackageID     int64
		VulnCount     int
		CriticalCount int
		HighCount     int
		MediumCount   int
		LowCount      int
	}
	err := db.WithContext(ctx).Model(&ScanResultModel{}).
		Select("id, package_id, scanned_at, vuln_count, critical_count, high_count, medium_count, low_count").
		Scan(&rows).Error
	if err != nil {
		return nil, time.Time{}, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read scans for backfill")
	}
	scans := map[int64][]backfillScan{}
	var firstScan time.Time
	for _, r := range rows {
		if _, ok := pkgs[r.PackageID]; !ok {
			continue
		}
		scans[r.PackageID] = append(scans[r.PackageID], backfillScan{
			id: r.ID, at: r.ScannedAt, vulns: r.VulnCount,
			critical: r.CriticalCount, high: r.HighCount, moderate: r.MediumCount, lowCounts: r.LowCount,
		})
		if d := r.ScannedAt.UTC().Truncate(day); firstScan.IsZero() || d.Before(firstScan) {
			firstScan = d
		}
	}
	for _, list := range scans {
		sort.Slice(list, func(i, j int) bool {
			if list[i].at.Equal(list[j].at) {
				return list[i].id < list[j].id
			}
			return list[i].at.Before(list[j].at)
		})
	}
	return scans, firstScan, nil
}
