package emulator

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewEmulator(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})
	if em == nil {
		t.Fatal("expected non-nil emulator")
	}
}

func TestPowershellEncodedCommand(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	err := em.powershellEncodedCommand(context.Background(), "SGVsbG8=")
	if err != nil {
		t.Fatalf("emulate T1059.001: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0]["event.type"] != "process_start" {
		t.Errorf("expected event.type 'process_start', got '%v'", events[0]["event.type"])
	}
	if events[0]["process.name"] != "powershell.exe" {
		t.Errorf("expected process.name 'powershell.exe', got '%v'", events[0]["process.name"])
	}
}

func TestOfficeSpawning(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	err := em.officeSpawning(context.Background())
	if err != nil {
		t.Fatalf("emulate T1566.001: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0]["process.parent.name"] != "winword.exe" {
		t.Errorf("expected parent 'winword.exe', got '%v'", events[0]["process.parent.name"])
	}
}

func TestLSASSAccess(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	err := em.lsassAccess(context.Background())
	if err != nil {
		t.Fatalf("emulate T1003.001: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0]["target.process.name"] != "lsass.exe" {
		t.Errorf("expected target 'lsass.exe', got '%v'", events[0]["target.process.name"])
	}
	if events[0]["severity"] != "critical" {
		t.Errorf("expected severity 'critical', got '%v'", events[0]["severity"])
	}
}

func TestRegistryPersistence(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	err := em.registryPersistence(context.Background())
	if err != nil {
		t.Fatalf("emulate T1547.001: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0]["event.type"] != "registry_set" {
		t.Errorf("expected event.type 'registry_set', got '%v'", events[0]["event.type"])
	}
}

func TestBeaconing(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := em.beaconing(ctx, "evil.com")
	if err != nil {
		t.Fatalf("emulate T1071: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 5 {
		t.Fatalf("expected 5 beacon events, got %d", len(events))
	}
	if events[0]["destination.domain"] != "evil.com" {
		t.Errorf("expected destination 'evil.com', got '%v'", events[0]["destination.domain"])
	}
}

func TestProcessInjection(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	err := em.processInjection(context.Background())
	if err != nil {
		t.Fatalf("emulate T1055: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0]["event.type"] != "create_remote_thread" {
		t.Errorf("expected event.type 'create_remote_thread', got '%v'", events[0]["event.type"])
	}
}

func TestRunTechnique(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	tests := []struct {
		technique string
		wantError bool
	}{
		{"T1059.001", false},
		{"T1566.001", false},
		{"T1003.001", false},
		{"T1547.001", false},
		{"T1055", false},
		{"T9999", true}, // unknown technique
	}

	for _, tc := range tests {
		mu.Lock()
		events = nil
		mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := em.Run(ctx, tc.technique, "")
		cancel()

		if tc.wantError && err == nil {
			t.Errorf("technique %s: expected error", tc.technique)
		}
		if !tc.wantError && err != nil {
			t.Errorf("technique %s: unexpected error: %v", tc.technique, err)
		}
	}
}

func TestRunScenario(t *testing.T) {
	var events []map[string]interface{}
	var mu sync.Mutex
	em := New(func(raw map[string]interface{}) {
		mu.Lock()
		events = append(events, raw)
		mu.Unlock()
	})

	err := em.RunScenario("ransomware_sim")
	if err != nil {
		t.Fatalf("run scenario: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 10 {
		t.Errorf("expected 10 ransomware events, got %d", len(events))
	}
}

func TestRunUnknownScenario(t *testing.T) {
	em := New(nil)
	err := em.RunScenario("nonexistent")
	if err == nil {
		t.Error("expected error for unknown scenario")
	}
}