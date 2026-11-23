package gormstore

import (
	"context"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"gorm.io/gorm"
)

// PurgeDeletedPackages hard-deletes up to limit soft-deleted packages deleted
// before deletedBefore, oldest id first, with the rows that reference them.
// Download history and stats snapshots hold no reference and stay.
func (s *GORMStoreV2) PurgeDeletedPackages(ctx context.Context, deletedBefore time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = metadata.DefaultBatchSize
	}
	var purged int64
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []int64
		if err := tx.Unscoped().Model(&PackageModel{}).
			Where("deleted_at IS NOT NULL AND deleted_at < ?", deletedBefore).
			Order("id").Limit(limit).Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		// The foreign keys cascade on PostgreSQL and MySQL; SQLite enforces them only when asked.
		for _, child := range []interface{}{&PackageVulnerabilityModel{}, &ScanResultModel{}, &PackageMetadataModel{}} {
			if err := tx.Unscoped().Where("package_id IN ?", ids).Delete(child).Error; err != nil {
				return err
			}
		}
		res := tx.Unscoped().Where("id IN ?", ids).Delete(&PackageModel{})
		purged = res.RowsAffected
		return res.Error
	})
	if err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to purge deleted packages")
	}
	return purged, nil
}
