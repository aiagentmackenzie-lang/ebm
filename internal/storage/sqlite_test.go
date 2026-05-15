package storage

import (
	"os"
	"testing"
	"time"

	"github.com/aiagentmackenzie-lang/ebm/internal/model"
)

func tempDB(t *testing.T) (*SQLiteQueue, string) {
	t.Helper()
	f, err := os.CreateTemp("", "ebm_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	q, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		q.Close()
		os.Remove(f.Name())
	})
	return q, f.Name()
}

func TestNewSQLiteQueue(t *testing.T) {
	q, _ := tempDB(t)
	if q == nil {
		t.Fatal("expected non-nil queue")
	}
}

func TestEnqueueDequeue(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{
		Timestamp:    time.Now().UTC(),
		EventType:    "process_start",
		ProcessName:  "test.exe",
		Severity:     "info",
		HostHostname: "test-host",
	}

	if err := q.Enqueue(ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	events, err := q.Dequeue(10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ProcessName != "test.exe" {
		t.Errorf("expected process name 'test.exe', got '%s'", events[0].ProcessName)
	}
}

func TestDequeueMarksSending(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	events, _ := q.Dequeue(10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Second dequeue should return nothing (event is in 'sending' state)
	events2, _ := q.Dequeue(10)
	if len(events2) != 0 {
		t.Errorf("expected 0 events on second dequeue, got %d", len(events2))
	}
}

func TestMarkSent(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	events, _ := q.Dequeue(10)
	if err := q.MarkSent(events); err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	// After marking sent, dequeue should return nothing
	events2, _ := q.Dequeue(10)
	if len(events2) != 0 {
		t.Errorf("expected 0 events after mark sent, got %d", len(events2))
	}
}

func TestRequeue(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	events, _ := q.Dequeue(10)

	// Requeue should put back to 'pending'
	if err := q.Requeue(events); err != nil {
		t.Fatalf("requeue: %v", err)
	}

	events2, _ := q.Dequeue(10)
	if len(events2) != 1 {
		t.Fatalf("expected 1 requeued event, got %d", len(events2))
	}
}

func TestRequeueMaxRetries(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	events, _ := q.Dequeue(10)

	// Requeue 5 times (retry_count goes 1,2,3,4,5)
	for i := 0; i < 5; i++ {
		q.Requeue(events)
		events, _ = q.Dequeue(10)
	}

	// After 5th requeue, retry_count >= 4, event should be 'failed', not 'pending'
	events2, _ := q.Dequeue(10)
	if len(events2) != 0 {
		t.Errorf("expected 0 events after max retries (should be failed), got %d", len(events2))
	}
}

func TestRecoverSending(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	// Dequeue puts event in 'sending' state
	_, _ = q.Dequeue(10)

	// RecoverSending should move it back to 'pending'
	if err := q.RecoverSending(); err != nil {
		t.Fatalf("recover sending: %v", err)
	}

	events, _ := q.Dequeue(10)
	if len(events) != 1 {
		t.Errorf("expected 1 recovered event, got %d", len(events))
	}
}

func TestPurgeOld(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	// Purge with 0 hours should remove everything
	if err := q.PurgeOld(0); err != nil {
		t.Fatalf("purge: %v", err)
	}

	events, _ := q.Dequeue(10)
	if len(events) != 0 {
		t.Errorf("expected 0 events after purge, got %d", len(events))
	}
}

func TestStats(t *testing.T) {
	q, _ := tempDB(t)

	ev := model.Event{Timestamp: time.Now().UTC(), EventType: "test", Severity: "info"}
	q.Enqueue(ev)

	pending, sending, sent, failed, err := q.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if pending != 1 {
		t.Errorf("expected 1 pending, got %d", pending)
	}
	if sending+sent+failed != 0 {
		t.Errorf("expected 0 sending/sent/failed, got sending=%d sent=%d failed=%d", sending, sent, failed)
	}
}

func TestEnqueueMultiple(t *testing.T) {
	q, _ := tempDB(t)

	for i := 0; i < 100; i++ {
		ev := model.Event{
			Timestamp:   time.Now().UTC(),
			EventType:   "test",
			Severity:    "info",
			ProcessName: "proc",
		}
		if err := q.Enqueue(ev); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	events, _ := q.Dequeue(50)
	if len(events) != 50 {
		t.Errorf("expected 50 events, got %d", len(events))
	}

	events2, _ := q.Dequeue(50)
	if len(events2) != 50 {
		t.Errorf("expected 50 events, got %d", len(events2))
	}
}

func TestDequeueEmpty(t *testing.T) {
	q, _ := tempDB(t)

	events, err := q.Dequeue(10)
	if err != nil {
		t.Fatalf("dequeue empty: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestMarkSentEmpty(t *testing.T) {
	q, _ := tempDB(t)

	if err := q.MarkSent(nil); err != nil {
		t.Fatalf("mark sent empty: %v", err)
	}
}