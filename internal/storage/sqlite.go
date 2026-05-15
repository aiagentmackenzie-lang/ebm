package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/aiagentmackenzie-lang/ebm/internal/model"
	_ "modernc.org/sqlite"
)

// SQLiteQueue is a persistent event queue backed by SQLite.
type SQLiteQueue struct {
	db *sql.DB
}

// New opens or creates the SQLite queue database.
func New(dbPath string) (*SQLiteQueue, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Serialize writes to prevent SQLITE_BUSY under concurrent goroutine access
	db.SetMaxOpenConns(1)

	// Enable WAL mode for concurrent reads + single writer
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	// Set busy timeout so concurrent writes wait instead of failing immediately
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}

	queue := &SQLiteQueue{db: db}
	if err := queue.migrate(); err != nil {
		return nil, err
	}
	return queue, nil
}

func (q *SQLiteQueue) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS event_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json TEXT NOT NULL,
    status TEXT CHECK(status IN ('pending','sending','sent','failed')) DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_status ON event_queue(status);
CREATE INDEX IF NOT EXISTS idx_created ON event_queue(created_at);
`
	_, err := q.db.Exec(schema)
	return err
}

// Enqueue inserts an event into the queue as pending.
func (q *SQLiteQueue) Enqueue(ev model.Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	_, err = q.db.Exec(
		"INSERT INTO event_queue (event_json, status) VALUES (?, 'pending')",
		string(data),
	)
	return err
}

// Dequeue returns up to n pending events and marks them 'sending'.
// Events remain recoverable until MarkSent deletes them after successful delivery.
func (q *SQLiteQueue) Dequeue(n int) ([]model.Event, error) {
	tx, err := q.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		"SELECT id, event_json FROM event_queue WHERE status = 'pending' ORDER BY created_at LIMIT ?",
		n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []model.Event
	var ids []int64
	for rows.Next() {
		var id int64
		var raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, err
		}
		ev.ID = id
		events = append(events, ev)
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return events, nil
	}

	// Mark as 'sending' — not yet confirmed delivered, so recoverable on crash
	for _, id := range ids {
		_, err := tx.Exec(
			"UPDATE event_queue SET status = 'sending', last_attempt_at = ? WHERE id = ?",
			time.Now().UTC(), id,
		)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// Requeue resets status to 'pending' for events that failed to send,
// incrementing retry_count. After 5 retries (retry_count >= 4 due to 0-index),
// events are marked 'failed' permanently.
func (q *SQLiteQueue) Requeue(events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	update, err := tx.Prepare("UPDATE event_queue SET status = CASE WHEN retry_count >= 4 THEN 'failed' ELSE 'pending' END, retry_count = retry_count + 1, last_attempt_at = ? WHERE id = ?")
	if err != nil {
		return err
	}
	defer update.Close()

	for _, ev := range events {
		if _, err := update.Exec(time.Now().UTC(), ev.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkSent permanently removes events from the queue.
func (q *SQLiteQueue) MarkSent(events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("DELETE FROM event_queue WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ev := range events {
		if _, err := stmt.Exec(ev.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RecoverSending resets events stuck in 'sending' status back to 'pending'.
// Called on startup to recover events that were dequeued but never confirmed sent.
func (q *SQLiteQueue) RecoverSending() error {
	result, err := q.db.Exec(
		"UPDATE event_queue SET status = 'pending', last_attempt_at = ? WHERE status = 'sending'",
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows > 0 {
		slog.Info("recovered sending events back to pending", "count", rows)
	}
	return nil
}

// Close closes the underlying database connection.
func (q *SQLiteQueue) Close() error {
	return q.db.Close()
}
