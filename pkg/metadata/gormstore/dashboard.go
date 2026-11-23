package gormstore

import (
	"context"
	stderrors "errors"
	"sort"
	"strconv"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"gorm.io/gorm"
)

// likeEscape is the ESCAPE character for search patterns; unlike a backslash it
// means the same thing on SQLite, PostgreSQL and MySQL.
const likeEscape = "!"

// scanErrorStatus marks a failed scan whose details decide whether it blocks.
const scanErrorStatus = string(metadata.ScanStatusError)

// baseNameExpr is the SQL that strips the Go "/@v/<file>" suffix from a package name.
func (s *GORMStoreV2) baseNameExpr() string {
	switch s.db.Name() {
	case "postgres":
		return "split_part(name, '/@v/', 1)"
	case "mysql":
		return "SUBSTRING_INDEX(name, '/@v/', 1)"
	default:
		return "CASE WHEN instr(name, '/@v/') > 0 THEN substr(name, 1, instr(name, '/@v/') - 1) ELSE name END"
	}
}

func escapeLike(q string) string {
	r := strings.NewReplacer(likeEscape, likeEscape+likeEscape, "%", likeEscape+"%", "_", likeEscape+"_")
	return "%" + r.Replace(strings.ToLower(q)) + "%"
}

// registryNames snapshots the id to name mapping.
func (s *GORMStoreV2) registryNames() map[int32]string {
	s.registryCacheMu.RLock()
	defer s.registryCacheMu.RUnlock()
	names := make(map[int32]string, len(s.registryCache))
	for name, id := range s.registryCache {
		names[id] = name
	}
	return names
}

// groupFilter builds the WHERE clause shared by the group count, the group page and the row fetch.
func (s *GORMStoreV2) groupFilter(opts metadata.GroupListOptions) (clause string, args []interface{}, empty bool, err error) {
	clause = "version NOT IN ?"
	args = []interface{}{metadata.MetadataVersions}
	if opts.Registry != "" {
		id, idErr := s.getRegistryID(opts.Registry)
		if idErr != nil {
			var hErr *errors.Error
			if stderrors.As(idErr, &hErr) && hErr.Code == errors.ErrCodeNotFound {
				return "", nil, true, nil
			}
			return "", nil, false, idErr
		}
		clause += " AND registry_id = ?"
		args = append(args, id)
	}
	if q := strings.TrimSpace(opts.Query); q != "" {
		like := escapeLike(q)
		clause += " AND (LOWER(name) LIKE ? ESCAPE '" + likeEscape + "'" +
			" OR LOWER(version) LIKE ? ESCAPE '" + likeEscape + "'" +
			" OR LOWER(release_version) LIKE ? ESCAPE '" + likeEscape + "')"
		args = append(args, like, like, like)
	}
	return clause, args, false, nil
}

// groupOrder is the ORDER BY of the group page query.
// It reads the aliases of the grouped subquery, which MySQL's only_full_group_by requires.
func groupOrder(opts metadata.GroupListOptions) string {
	dir := "ASC"
	if opts.SortDesc {
		dir = "DESC"
	}
	var lead string
	switch opts.SortBy {
	case metadata.GroupSortCachedAt:
		lead = "last_cached " + dir + ", "
	case metadata.GroupSortDownloads:
		lead = "downloads " + dir + ", "
	case metadata.GroupSortSize:
		lead = "total_size " + dir + ", "
	}
	nameDir := "ASC"
	if lead == "" && opts.SortDesc {
		nameDir = "DESC"
	}
	return lead + "LOWER(base_name) " + nameDir + ", base_name " + nameDir + ", registry_id ASC"
}

type groupKey struct {
	name       string
	registryID int32
}

// ListPackageGroups returns one page of groups with all their version rows in four statements at most.
func (s *GORMStoreV2) ListPackageGroups(ctx context.Context, opts metadata.GroupListOptions) (*metadata.GroupPage, error) {
	page := &metadata.GroupPage{}
	clause, args, empty, err := s.groupFilter(opts)
	if err != nil {
		return nil, err
	}
	if empty {
		return page, nil
	}
	base := s.baseNameExpr()
	matching := func() *gorm.DB {
		return s.db.WithContext(ctx).Model(&PackageModel{}).Where(clause, args...)
	}

	var rows []PackageModel
	if opts.PageSize <= 0 {
		// Everything is wanted, so order the groups in memory with the reference implementation.
		if err := matching().Find(&rows).Error; err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list packages")
		}
		opts.Registry, opts.Query = "", ""
		return metadata.PageGroups(s.modelsToPackages(rows), opts), nil
	}

	distinct := matching().
		Select("registry_id, " + base + " AS base_name, MAX(cached_at) AS last_cached, SUM(access_count) AS downloads, SUM(size) AS total_size").
		Group("registry_id, " + base)
	if err := s.db.WithContext(ctx).Table("(?) AS g", distinct).Select("COUNT(*)").Scan(&page.TotalGroups).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to count package groups")
	}
	if page.TotalGroups == 0 {
		return page, nil
	}

	pageNo := opts.Page
	if pageNo < 1 {
		pageNo = 1
	}
	var keys []struct {
		BaseName   string
		RegistryID int32
	}
	if err := s.db.WithContext(ctx).Table("(?) AS g", distinct).Select("registry_id, base_name").
		Order(groupOrder(opts)).
		Limit(opts.PageSize).Offset((pageNo - 1) * opts.PageSize).
		Scan(&keys).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to page package groups")
	}
	if len(keys) == 0 {
		return page, nil
	}
	order := make([]groupKey, len(keys))
	registryIDs := make([]int32, 0, len(keys))
	names := make([]string, 0, len(keys))
	for i, k := range keys {
		order[i] = groupKey{name: k.BaseName, registryID: k.RegistryID}
		registryIDs = append(registryIDs, k.RegistryID)
		names = append(names, k.BaseName)
	}

	if err := matching().
		Where("registry_id IN ? AND "+base+" IN ?", registryIDs, names).
		Order("cached_at DESC").Find(&rows).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list group packages")
	}
	return s.orderGroupRows(page, rows, order), nil
}

// orderGroupRows converts rows, dedupes Go file variants and sorts them into the page's group order.
func (s *GORMStoreV2) orderGroupRows(page *metadata.GroupPage, rows []PackageModel, order []groupKey) *metadata.GroupPage {
	names := s.registryNames()
	rank := make(map[string]int, len(order))
	for i, k := range order {
		rank[names[k.registryID]+"\x00"+k.name] = i
	}
	var kept []*metadata.Package
	for _, p := range metadata.DedupeVersions(s.modelsToPackages(rows)) {
		if _, ok := rank[p.Registry+"\x00"+p.Name]; ok {
			kept = append(kept, p)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		return rank[kept[i].Registry+"\x00"+kept[i].Name] < rank[kept[j].Registry+"\x00"+kept[j].Name]
	})
	page.Packages = kept
	return page
}

// GetScanSummaries returns the latest scan per package in two statements (three when a scan failed and details are lazily loaded).
func (s *GORMStoreV2) GetScanSummaries(ctx context.Context, packageIDs []string, withDetails bool) ([]*metadata.ScanSummary, error) {
	var ids []int64
	for _, raw := range packageIDs {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if packageIDs != nil && len(ids) == 0 {
		return nil, nil
	}

	pkgQuery := s.db.WithContext(ctx).Model(&PackageModel{}).
		Select("id, registry_id, name, version, release_version").
		Where("security_scanned = ?", true)
	if packageIDs != nil {
		pkgQuery = pkgQuery.Where("id IN ?", ids)
	}
	var pkgs []PackageModel
	if err := pkgQuery.Order("id").Find(&pkgs).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to load scanned packages")
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	columns := "id, package_id, status, scanned_at, vuln_count, critical_count, high_count, medium_count, low_count"
	if withDetails {
		columns += ", details"
	}
	scanQuery := s.db.WithContext(ctx).Model(&ScanResultModel{}).Select(columns).
		Where("scanned_at = (SELECT MAX(x.scanned_at) FROM scan_results x WHERE x.package_id = scan_results.package_id AND x.deleted_at IS NULL)")
	if packageIDs != nil {
		scanQuery = scanQuery.Where("package_id IN ?", ids)
	} else {
		scanQuery = scanQuery.Where("package_id IN (SELECT id FROM packages WHERE security_scanned = ? AND deleted_at IS NULL)", true)
	}
	var scans []ScanResultModel
	if err := scanQuery.Find(&scans).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to load scan results")
	}
	latest := make(map[int64]*ScanResultModel, len(scans))
	for i := range scans {
		// Equal timestamps return two rows; the newer insert wins.
		if cur, ok := latest[scans[i].PackageID]; !ok || scans[i].ID > cur.ID {
			latest[scans[i].PackageID] = &scans[i]
		}
	}

	if !withDetails {
		if err := s.loadFailedScanDetails(ctx, latest); err != nil {
			return nil, err
		}
	}

	names := s.registryNames()
	out := make([]*metadata.ScanSummary, 0, len(pkgs))
	for i := range pkgs {
		p := &pkgs[i]
		sum := &metadata.ScanSummary{
			Registry:       names[p.RegistryID],
			PackageID:      strconv.FormatInt(p.ID, 10),
			Name:           p.Name,
			Version:        p.Version,
			ReleaseVersion: p.ReleaseVersion,
		}
		if scan, ok := latest[p.ID]; ok {
			sum.HasScan = true
			sum.Status = metadata.ScanStatus(scan.Status)
			sum.ScannedAt = scan.ScannedAt
			sum.Total = scan.VulnCount
			sum.Critical = scan.CriticalCount
			sum.High = scan.HighCount
			sum.Moderate = scan.MediumCount
			sum.Low = scan.LowCount
			if withDetails {
				sum.Vulnerabilities = vulnerabilitiesFromDetails(scan.Details)
			}
			if scan.Status == scanErrorStatus || withDetails {
				sum.Details = map[string]interface{}(scan.Details)
			}
		}
		out = append(out, sum)
	}
	return out, nil
}

// loadFailedScanDetails fills Details for failed scans, which carry the infrastructure-error flag.
func (s *GORMStoreV2) loadFailedScanDetails(ctx context.Context, latest map[int64]*ScanResultModel) error {
	var failed []int64
	for _, scan := range latest {
		if scan.Status == scanErrorStatus {
			failed = append(failed, scan.ID)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	var rows []ScanResultModel
	if err := s.db.WithContext(ctx).Model(&ScanResultModel{}).
		Select("id, details").Where("id IN ?", failed).Find(&rows).Error; err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to load failed scan details")
	}
	details := make(map[int64]JSONBField, len(rows))
	for _, r := range rows {
		details[r.ID] = r.Details
	}
	for _, scan := range latest {
		if scan.Status == scanErrorStatus {
			scan.Details = details[scan.ID]
		}
	}
	return nil
}

// GetRegistryStats groups cache artifacts by registry in one statement.
func (s *GORMStoreV2) GetRegistryStats(ctx context.Context) ([]metadata.RegistryStat, error) {
	var rows []struct {
		RegistryID int32
		Count      int64
		Size       int64
		Downloads  int64
	}
	if err := s.db.WithContext(ctx).Model(&PackageModel{}).
		Select("registry_id, COUNT(*) AS count, COALESCE(SUM(size), 0) AS size, COALESCE(SUM(access_count), 0) AS downloads").
		Where("version NOT IN ?", metadata.MetadataVersions).
		Group("registry_id").Order("registry_id").
		Scan(&rows).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to aggregate registry stats")
	}
	names := s.registryNames()
	out := make([]metadata.RegistryStat, 0, len(rows))
	for _, r := range rows {
		out = append(out, metadata.RegistryStat{Registry: names[r.RegistryID], Count: r.Count, Size: r.Size, Downloads: r.Downloads})
	}
	return out, nil
}

// vulnerabilitiesFromDetails decodes the vulnerability list stored in a scan's details.
func vulnerabilitiesFromDetails(details JSONBField) []metadata.Vulnerability {
	var vulnerabilities []metadata.Vulnerability
	vulnArray, ok := details["vulnerabilities"].([]interface{})
	if !ok {
		return nil
	}
	for _, v := range vulnArray {
		vulnMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		vuln := metadata.Vulnerability{
			ID:          getStringFromMap(vulnMap, "id"),
			Severity:    getStringFromMap(vulnMap, "severity"),
			Title:       getStringFromMap(vulnMap, "title"),
			Description: getStringFromMap(vulnMap, "description"),
			FixedIn:     getStringFromMap(vulnMap, "fixed_in"),
		}
		if refs, ok := vulnMap["references"].([]interface{}); ok {
			for _, ref := range refs {
				if refStr, ok := ref.(string); ok {
					vuln.References = append(vuln.References, refStr)
				}
			}
		}
		if detectedBy, ok := vulnMap["detected_by"].([]interface{}); ok {
			for _, d := range detectedBy {
				if dStr, ok := d.(string); ok {
					vuln.DetectedBy = append(vuln.DetectedBy, dStr)
				}
			}
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	return vulnerabilities
}
