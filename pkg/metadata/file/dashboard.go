package file

import (
	"context"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// packageKey identifies a file-store record, which has no numeric id.
func packageKey(p *metadata.Package) string {
	return p.Registry + "/" + p.Name + "@" + p.Version
}

// listRecords returns package records only: the store's walk also yields scan result files.
func (s *Store) listRecords(ctx context.Context) ([]*metadata.Package, error) {
	all, err := s.ListPackages(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, p := range all {
		if p.Registry != "" && p.Name != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// ListPackageGroups pages groups in memory.
func (s *Store) ListPackageGroups(ctx context.Context, opts metadata.GroupListOptions) (*metadata.GroupPage, error) {
	all, err := s.listRecords(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range all {
		if p.ID == "" {
			p.ID = packageKey(p)
		}
	}
	if len(opts.Severities) > 0 {
		if all, err = s.withSeverity(ctx, all, opts.Severities); err != nil {
			return nil, err
		}
	}
	return metadata.PageGroups(all, opts), nil
}

// withSeverity keeps the packages whose scan holds a vulnerability of one of the severities.
func (s *Store) withSeverity(ctx context.Context, all []*metadata.Package, severities []string) ([]*metadata.Package, error) {
	sums, err := s.GetScanSummaries(ctx, nil, false)
	if err != nil {
		return nil, err
	}
	hit := make(map[string]struct{}, len(sums))
	for _, sum := range sums {
		for _, sev := range severities {
			if (sev == metadata.SeverityCritical && sum.Critical > 0) || (sev == metadata.SeverityHigh && sum.High > 0) ||
				(sev == metadata.SeverityModerate && sum.Moderate > 0) || (sev == metadata.SeverityLow && sum.Low > 0) {
				hit[sum.PackageID] = struct{}{}
				break
			}
		}
	}
	out := all[:0]
	for _, p := range all {
		if _, ok := hit[p.ID]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// GetScanSummaries reads each scanned package's latest scan file.
func (s *Store) GetScanSummaries(ctx context.Context, packageIDs []string, withDetails bool) ([]*metadata.ScanSummary, error) {
	all, err := s.listRecords(ctx)
	if err != nil {
		return nil, err
	}
	want := make(map[string]struct{}, len(packageIDs))
	for _, id := range packageIDs {
		want[id] = struct{}{}
	}
	var out []*metadata.ScanSummary
	for _, p := range all {
		id := p.ID
		if id == "" {
			id = packageKey(p)
		}
		if _, ok := want[id]; packageIDs != nil && !ok || !p.SecurityScanned {
			continue
		}
		sum := &metadata.ScanSummary{
			Registry: p.Registry, PackageID: id, Name: p.Name, Version: p.Version, ReleaseVersion: p.ReleaseVersion,
		}
		res, err := s.GetScanResult(ctx, p.Registry, p.Name, p.Version)
		if err != nil {
			return nil, err
		}
		if res != nil {
			sum.HasScan = true
			sum.Status = res.Status
			sum.ScannedAt = res.ScannedAt
			sum.Total = res.VulnerabilityCount
			sum.Details = res.Details
			for _, v := range res.Vulnerabilities {
				switch metadata.NormalizeSeverity(v.Severity) {
				case "CRITICAL":
					sum.Critical++
				case "HIGH":
					sum.High++
				case "MODERATE":
					sum.Moderate++
				default:
					sum.Low++
				}
			}
			if withDetails {
				sum.Vulnerabilities = res.Vulnerabilities
			}
		}
		out = append(out, sum)
	}
	return out, nil
}

// GetRegistryStats totals artifacts per registry.
func (s *Store) GetRegistryStats(ctx context.Context) ([]metadata.RegistryStat, error) {
	all, err := s.listRecords(ctx)
	if err != nil {
		return nil, err
	}
	byRegistry := map[string]*metadata.RegistryStat{}
	var order []string
	for _, p := range all {
		if metadata.IsMetadataEntry(p.Registry, p.Name, p.Version) {
			continue
		}
		st, ok := byRegistry[p.Registry]
		if !ok {
			st = &metadata.RegistryStat{Registry: p.Registry}
			byRegistry[p.Registry] = st
			order = append(order, p.Registry)
		}
		st.Count++
		st.Size += p.Size
		st.Downloads += p.DownloadCount
	}
	out := make([]metadata.RegistryStat, 0, len(order))
	for _, r := range order {
		out = append(out, *byRegistry[r])
	}
	return out, nil
}
