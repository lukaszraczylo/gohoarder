package metadata

import (
	"sort"
	"strings"
)

// IsMetadataVersion reports whether version names a metadata page rather than an artifact.
func IsMetadataVersion(version string) bool {
	for _, v := range MetadataVersions {
		if version == v {
			return true
		}
	}
	return false
}

// MatchesQuery reports whether a package matches a case-insensitive search on name, version or release version.
func MatchesQuery(p *Package, query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	return strings.Contains(strings.ToLower(p.Name), q) ||
		strings.Contains(strings.ToLower(p.Version), q) ||
		strings.Contains(strings.ToLower(p.ReleaseVersion), q)
}

type groupAgg struct {
	registry, name string
	rows           []*Package
	last           int64
	size, dl       int64
}

// PageGroups filters, groups, sorts and pages rows in memory. It is the reference
// behaviour that SQL backends of ListPackageGroups must match.
func PageGroups(all []*Package, opts GroupListOptions) *GroupPage {
	groups := map[string]*groupAgg{}
	for _, p := range all {
		if IsMetadataEntry(p.Registry, p.Name, p.Version) || (opts.Registry != "" && p.Registry != opts.Registry) || !MatchesQuery(p, opts.Query) {
			continue
		}
		name := CleanName(p.Name)
		key := p.Registry + "\x00" + name
		g, ok := groups[key]
		if !ok {
			g = &groupAgg{registry: p.Registry, name: name}
			groups[key] = g
		}
		if ts := p.CachedAt.UnixNano(); ts > g.last {
			g.last = ts
		}
		g.size += p.Size
		g.dl += p.DownloadCount
		g.rows = append(g.rows, p)
	}

	ordered := make([]*groupAgg, 0, len(groups))
	for _, g := range groups {
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		var cmp int
		switch opts.SortBy {
		case GroupSortCachedAt:
			cmp = compareInt(a.last, b.last)
		case GroupSortDownloads:
			cmp = compareInt(a.dl, b.dl)
		case GroupSortSize:
			cmp = compareInt(a.size, b.size)
		}
		if cmp != 0 {
			if opts.SortDesc {
				return cmp > 0
			}
			return cmp < 0
		}
		if c := strings.Compare(strings.ToLower(a.name), strings.ToLower(b.name)); c != 0 {
			if opts.SortBy == "" || opts.SortBy == GroupSortName {
				if opts.SortDesc {
					return c > 0
				}
			}
			return c < 0
		}
		return a.registry < b.registry
	})

	page := &GroupPage{TotalGroups: int64(len(ordered))}
	if opts.PageSize > 0 {
		pageNo := opts.Page
		if pageNo < 1 {
			pageNo = 1
		}
		start := (pageNo - 1) * opts.PageSize
		if start >= len(ordered) {
			return page
		}
		end := start + opts.PageSize
		if end > len(ordered) {
			end = len(ordered)
		}
		ordered = ordered[start:end]
	}
	for _, g := range ordered {
		sort.SliceStable(g.rows, func(i, j int) bool { return g.rows[i].CachedAt.After(g.rows[j].CachedAt) })
		page.Packages = append(page.Packages, DedupeVersions(g.rows)...)
	}
	return page
}

func compareInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
