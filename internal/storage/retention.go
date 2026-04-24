package storage

import (
	"log/slog"
	"time"
)

// PurgeOld removes events older than the configured retention window.
func (q *SQLiteQueue) PurgeOld(retentionHours int) error {
	cutoff := time.Now().UTC().Add(-time.Duration(retentionHours) * time.Hour)
	res, err := q.db.Exec("DELETE FROM event_queue WHERE created_at < ?", cutoff)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows > 0 {
		slog.Info("purged old events", "count", rows)
	}
	return nil
}

// Stats returns queue statistics for observability.
func (q *SQLiteQueue) Stats() (pending, sent, failed int64, err error) {
	if err := q.db.QueryRow("SELECT COUNT(*) FROM event_queue WHERE status='pending'").Scan(&pending); err != nil {
		return 0, 0, 0, err
	}
	if err := q.db.QueryRow("SELECT COUNT(*) FROM event_queue WHERE status='sent'").Scan(&sent); err != nil {
		return 0, 0, 0, err
	}
	if err := q.db.QueryRow("SELECT COUNT(*) FROM event_queue WHERE status='failed'").Scan(&failed); err != nil {
		return 0, 0, 0, err
	}
	return
}

// Vacuum reclaims free space from the SQLite database.
func (q *SQLiteQueue) Vacuum() error {
	_, err := q.db.Exec("VACUUM")
	return err
}
