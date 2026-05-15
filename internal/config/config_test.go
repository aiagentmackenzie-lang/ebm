package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	content := `
agent:
  id: "test-agent"
  version: "1.0.0"
  log_level: "debug"
siem:
  url: "http://localhost:8000/api/v1/ingest"
  bearer_token: "test-token-123"
  batch_size: 25
  flush_interval_sec: 5
  health_check_url: "http://localhost:8000/api/v1/health"
  health_check_interval_sec: 15
  timeout_sec: 5
collection:
  enabled: true
  process_events: true
  network_events: true
rules:
  enabled: true
  rules_dir: "./rules"
storage:
  db_path: "./test_queue.db"
  max_size_mb: 50
  retention_hours: 24
`
	f, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Agent.ID != "test-agent" {
		t.Errorf("expected agent id 'test-agent', got '%s'", cfg.Agent.ID)
	}
	if cfg.SIEM.BearerToken != "test-token-123" {
		t.Errorf("expected bearer token, got '%s'", cfg.SIEM.BearerToken)
	}
	if cfg.SIEM.BatchSize != 25 {
		t.Errorf("expected batch size 25, got %d", cfg.SIEM.BatchSize)
	}
	if cfg.Storage.MaxSizeMB != 50 {
		t.Errorf("expected max_size_mb 50, got %d", cfg.Storage.MaxSizeMB)
	}
}

func TestConfigValidationMissingToken(t *testing.T) {
	content := `
agent:
  id: "test-agent"
siem:
  url: "http://localhost:8000/api/v1/ingest"
  bearer_token: ""
`
	f, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for missing bearer token")
	}
}

func TestConfigValidationUnresolvedEnvVar(t *testing.T) {
	content := `
agent:
  id: "test-agent"
siem:
  url: "http://localhost:8000/api/v1/ingest"
  bearer_token: "${NONEXISTENT_VAR_12345}"
`
	f, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for unresolved env var in bearer token")
	}
}

func TestConfigDefaults(t *testing.T) {
	content := `
siem:
  url: "http://localhost:8000/api/v1/ingest"
  bearer_token: "test-token"
`
	f, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.SIEM.BatchSize != 50 {
		t.Errorf("expected default batch size 50, got %d", cfg.SIEM.BatchSize)
	}
	if cfg.SIEM.FlushIntervalSec != 10 {
		t.Errorf("expected default flush interval 10, got %d", cfg.SIEM.FlushIntervalSec)
	}
	if cfg.SIEM.TimeoutSec != 10 {
		t.Errorf("expected default timeout 10, got %d", cfg.SIEM.TimeoutSec)
	}
	if cfg.Storage.RetentionHours != 72 {
		t.Errorf("expected default retention 72, got %d", cfg.Storage.RetentionHours)
	}
}

func TestGenerateAgentID(t *testing.T) {
	id1 := generateAgentID()
	id2 := generateAgentID()
	if id1 == id2 {
		t.Error("expected different agent IDs, got identical")
	}
	if len(id1) < 10 {
		t.Errorf("expected agent ID length >= 10, got %d", len(id1))
	}
}