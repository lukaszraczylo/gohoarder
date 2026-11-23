package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// newRollupStore adds the unique indexes Postgres gets from the partition manager,
// so INSERT OR REPLACE upserts as the ON CONFLICT clauses do there.
func newRollupStore(t *testing.T) *GORMStoreV2 {
	t.Helper()
	store := newTimeSeriesStore(t)
	for _, stmt := range statsUpsertIndexes {
		require.NoError(t, store.db.Exec(stmt).Error)
	}
	return store
}

// tick mirrors AggregationWorker.Start: an hourly pass, plus the daily pass in hour 0.
func tick(t *testing.T, store *GORMStoreV2, at time.Time, daily bool) {
	t.Helper()
	store.aggregationWorker.now = func() time.Time { return at }
	require.NoError(t, store.aggregationWorker.AggregateHourly())
	if daily && at.Hour() == 0 {
		require.NoError(t, store.aggregationWorker.AggregateDaily())
	}
}

func seedEventsAt(t *testing.T, store *GORMStoreV2, times ...time.Time) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.3.0", StorageKey: "npm/left-pad/1.3.0",
		Size: 10, CachedAt: times[0], LastAccessed: times[0],
	}))
	for _, at := range times {
		require.NoError(t, store.UpdateDownloadCount(ctx, "npm", "left-pad", "1.3.0"))
		var id int64
		require.NoError(t, store.db.Table("download_events").Select("MAX(id)").Scan(&id).Error)
		require.NoError(t, store.db.Exec("UPDATE download_events SET downloaded_at = ? WHERE id = ?", at, id).Error)
	}
}

func totalAt(t *testing.T, store *GORMStoreV2, at time.Time, period string) int64 {
	t.Helper()
	store.now = func() time.Time { return at }
	ts, err := store.GetTimeSeriesStats(context.Background(), period, "")
	require.NoError(t, err)
	return sumPoints(ts)
}

// A download in the last hour of a day that the daily pass ran before that hour was aggregated.
func TestDailyRollupKeepsLastHourOfDay(t *testing.T) {
	store := newRollupStore(t)
	day := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	seedEventsAt(t, store, day.Add(10*time.Hour), day.Add(23*time.Hour+30*time.Minute))

	tick(t, store, day.Add(24*time.Hour+2*time.Minute), true) // cutoff 23:00: the 23:30 event is not counted yet
	tick(t, store, day.Add(25*time.Hour+2*time.Minute), true)
	tick(t, store, day.Add(48*time.Hour+3*time.Minute), true)

	require.EqualValues(t, 2, totalAt(t, store, day.Add(48*time.Hour+10*time.Minute), "7day"))
}

// A day whose midnight daily pass never ran must still be rolled up before its hourly rows expire.
func TestDailyRollupCoversMissedDay(t *testing.T) {
	store := newRollupStore(t)
	day := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	seedEventsAt(t, store, day.Add(5*time.Hour), day.Add(6*time.Hour), day.Add(7*time.Hour))

	tick(t, store, day.Add(24*time.Hour+30*time.Minute), false) // process restarting at midnight: no daily pass
	for d := 2; d <= 9; d++ {
		tick(t, store, day.Add(time.Duration(d)*24*time.Hour+30*time.Minute), true)
	}

	require.EqualValues(t, 3, totalAt(t, store, day.Add(9*24*time.Hour+time.Hour), "30day"))
}
