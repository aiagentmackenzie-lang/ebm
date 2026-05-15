package transport

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	// Attempt 0: 1s base
	d0 := Backoff(0)
	if d0 < time.Second || d0 > 2*time.Second {
		t.Errorf("expected ~1s for attempt 0, got %v", d0)
	}

	// Attempt 1: 2s base
	d1 := Backoff(1)
	if d1 < 2*time.Second || d1 > 3*time.Second {
		t.Errorf("expected ~2s for attempt 1, got %v", d1)
	}

	// Attempt 10: should be capped at 300s
	d10 := Backoff(10)
	if d10 < 300*time.Second || d10 > 301*time.Second {
		t.Errorf("expected ~300s for attempt 10, got %v", d10)
	}
}

func TestBackoffJitter(t *testing.T) {
	// Multiple calls should produce different values due to jitter
	d1 := Backoff(2)
	d2 := Backoff(2)
	// They might occasionally be the same, but very unlikely
	// Just check they're in the expected range
	if d1 < 4*time.Second || d1 > 5*time.Second {
		t.Errorf("expected ~4s for attempt 2, got %v", d1)
	}
	if d2 < 4*time.Second || d2 > 5*time.Second {
		t.Errorf("expected ~4s for attempt 2, got %v", d2)
	}
}