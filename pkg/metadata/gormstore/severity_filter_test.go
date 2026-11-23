package gormstore

import (
	"context"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func checkSeverityFilter(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	for _, n := range []string{"crit", "high", "mod", "low", "clean", "fixed", "multi", "unscanned"} {
		seedAt(t, store, n, "1.0.0", 1, daysAgo(3))
	}
	scanAt(t, store, "crit", "1.0.0", daysAgo(2), "critical")
	scanAt(t, store, "high", "1.0.0", daysAgo(2), "high")
	scanAt(t, store, "mod", "1.0.0", daysAgo(2), "moderate")
	scanAt(t, store, "low", "1.0.0", daysAgo(2), "low")
	scanAt(t, store, "clean", "1.0.0", daysAgo(2))
	scanAt(t, store, "fixed", "1.0.0", daysAgo(2), "critical")
	scanAt(t, store, "fixed", "1.0.0", daysAgo(1)) // the newest scan decides
	scanAt(t, store, "multi", "1.0.0", daysAgo(2), "high", "low")

	pick := func(opts metadata.GroupListOptions) []string {
		page, err := store.ListPackageGroups(ctx, opts)
		require.NoError(t, err)
		out := names(page.Packages)
		for i := range out {
			for j := i + 1; j < len(out); j++ {
				if out[j] < out[i] {
					out[i], out[j] = out[j], out[i]
				}
			}
		}
		return out
	}

	require.Equal(t, []string{"crit"}, pick(metadata.GroupListOptions{Severities: []string{"critical"}}))
	require.Equal(t, []string{"high", "multi"}, pick(metadata.GroupListOptions{Severities: []string{"high"}}))
	require.Equal(t, []string{"crit", "mod"}, pick(metadata.GroupListOptions{Severities: []string{"critical", "moderate"}}), "OR across severities")
	require.Equal(t, []string{"low", "multi"}, pick(metadata.GroupListOptions{Severities: []string{"low"}}))
	require.Equal(t, []string{"crit", "high", "low", "mod", "multi"},
		pick(metadata.GroupListOptions{Severities: metadata.Severities}), "every severity = every vulnerable package")
	require.Len(t, pick(metadata.GroupListOptions{}), 8, "no filter keeps everything")

	paged, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Severities: []string{"high", "low"}, Page: 1, PageSize: 2})
	require.NoError(t, err)
	require.EqualValues(t, 3, paged.TotalGroups, "paging counts the filtered groups")
	require.Len(t, paged.Packages, 2)

	require.Equal(t, []string{"crit"}, pick(metadata.GroupListOptions{Severities: []string{"critical"}, Query: "cr"}), "composes with search")
	require.Empty(t, pick(metadata.GroupListOptions{Severities: []string{"critical"}, Query: "high"}))
}

func checkSeverityFilterStatementsAreConstant(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	counter := attachCounter(store)
	measure := func() [2]int {
		var out [2]int
		counter.Reset()
		_, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Severities: []string{"critical", "high"}})
		require.NoError(t, err)
		out[0] = counter.Count()
		counter.Reset()
		_, err = store.ListPackageGroups(ctx, metadata.GroupListOptions{Severities: []string{"low"}, Page: 1, PageSize: 25})
		require.NoError(t, err)
		out[1] = counter.Count()
		return out
	}
	seedScanned(t, store, 0, 10)
	small := measure()
	seedScanned(t, store, 10, 90)
	large := measure()
	t.Logf("statements for 10 rows %v, for 100 rows %v", small, large)
	require.Equal(t, small, large)
	require.LessOrEqual(t, large[0], 1, "the filter is a subquery of the one list read")
	require.LessOrEqual(t, large[1], 3)
}

func TestSeverityFilter(t *testing.T) { checkSeverityFilter(t, newTimeSeriesStore(t)) }
func TestSeverityFilterStatementsAreConstant(t *testing.T) {
	checkSeverityFilterStatementsAreConstant(t, newTimeSeriesStore(t))
}
