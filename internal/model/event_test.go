package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventToJSON(t *testing.T) {
	ev := Event{
		Timestamp:     time.Now().UTC(),
		EventType:     "process_start",
		ProcessName:   "bash",
		ProcessPID:    1234,
		Severity:      "info",
		HostHostname:  "test-host",
		RawData:       map[string]interface{}{"key": "value"},
	}

	data, err := ev.ToJSON()
	if err != nil {
		t.Fatalf("toJSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["process.name"] != "bash" {
		t.Errorf("expected 'bash', got '%v'", parsed["process.name"])
	}
}

func TestEventJSONSerialization(t *testing.T) {
	ev := Event{
		Timestamp:     time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		EventType:     "network_connect",
		HostHostname:  "host-01",
		SourceIP:      "10.0.0.1",
		DestIP:        "93.184.216.34",
		DestPort:      443,
		MITRETIDs:    []string{"T1071"},
		MITRETactic:  "Command and Control",
	}

	data, err := ev.ToJSON()
	if err != nil {
		t.Fatalf("toJSON: %v", err)
	}

	// Verify it round-trips
	var ev2 Event
	if err := json.Unmarshal(data, &ev2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev2.EventType != "network_connect" {
		t.Errorf("expected 'network_connect', got '%s'", ev2.EventType)
	}
	if ev2.DestPort != 443 {
		t.Errorf("expected DestPort 443, got %d", ev2.DestPort)
	}
}

func TestIngestEventSerialization(t *testing.T) {
	ev := Event{
		Timestamp:    time.Now().UTC(),
		EventType:    "process_start",
		ProcessName:  "test",
		Severity:     "high",
		HostHostname: "host",
	}

	ie := IngestEvent{
		Timestamp:     ev.Timestamp,
		HostName:      ev.HostHostname,
		Source:        "endpoint_behavior_monitor",
		EventCategory: "process",
		EventType:     "start",
		ProcessName:   ev.ProcessName,
		Severity:      ev.Severity,
	}

	data, err := json.Marshal(ie)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["source"] != "endpoint_behavior_monitor" {
		t.Errorf("expected source field, got '%v'", parsed["source"])
	}
}

func TestAlertSerialization(t *testing.T) {
	a := Alert{
		RuleID:      "test-001",
		RuleName:    "Test Rule",
		Timestamp:   time.Now().UTC(),
		Severity:    "critical",
		MITRETIDs:  []string{"T1059.001"},
		MITRETactic: "Execution",
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["rule_id"] != "test-001" {
		t.Errorf("expected rule_id 'test-001', got '%v'", parsed["rule_id"])
	}
}