package normalizer

import (
	"testing"
)

func TestNormalizeProcessEvent(t *testing.T) {
	raw := map[string]interface{}{
		"event.type":           "process_start",
		"event.platform":       "linux",
		"event.provider":       "ebpf",
		"host.hostname":        "devbox-01",
		"process.name":         "bash",
		"process.command_line": "bash -c whoami",
		"process.pid":          1234,
		"process.parent.pid":   1,
		"process.parent.name":  "systemd",
		"user.name":            "root",
		"user.id":              "0",
		"severity":             "high",
	}

	ev := Normalize(raw)
	if ev.EventType != "process_start" {
		t.Errorf("expected event.type 'process_start', got '%s'", ev.EventType)
	}
	if ev.ProcessName != "bash" {
		t.Errorf("expected process.name 'bash', got '%s'", ev.ProcessName)
	}
	if ev.ProcessPID != 1234 {
		t.Errorf("expected process.pid 1234, got %d", ev.ProcessPID)
	}
	if ev.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", ev.Severity)
	}
	if ev.HostHostname != "devbox-01" {
		t.Errorf("expected host.hostname 'devbox-01', got '%s'", ev.HostHostname)
	}
}

func TestNormalizeNetworkEvent(t *testing.T) {
	raw := map[string]interface{}{
		"event.type":          "network_connect",
		"source.ip":           "10.0.0.15",
		"source.port":         54321,
		"destination.ip":     "93.184.216.34",
		"destination.port":   443,
		"destination.domain": "example.com",
		"network.direction":   "outbound",
		"network.transport":   "tcp",
	}

	ev := Normalize(raw)
	if ev.EventType != "network_connect" {
		t.Errorf("expected event.type 'network_connect', got '%s'", ev.EventType)
	}
	if ev.SourceIP != "10.0.0.15" {
		t.Errorf("expected source.ip '10.0.0.15', got '%s'", ev.SourceIP)
	}
	if ev.DestPort != 443 {
		t.Errorf("expected destination.port 443, got %d", ev.DestPort)
	}
	if ev.DestDomain != "example.com" {
		t.Errorf("expected destination.domain 'example.com', got '%s'", ev.DestDomain)
	}
}

func TestNormalizeDefaults(t *testing.T) {
	raw := map[string]interface{}{
		"event.type": "unknown_type",
	}

	ev := Normalize(raw)
	if ev.EventPlatform != "unknown" {
		t.Errorf("expected default platform 'unknown', got '%s'", ev.EventPlatform)
	}
	if ev.Severity != "info" {
		t.Errorf("expected default severity 'info', got '%s'", ev.Severity)
	}
	if ev.ProcessPID != 0 {
		t.Errorf("expected default PID 0, got %d", ev.ProcessPID)
	}
}

func TestNormalizeIntTypeConversions(t *testing.T) {
	// JSON/YAML unmarshalling may produce float64 for numbers
	raw := map[string]interface{}{
		"event.type":   "test",
		"process.pid":  float64(999),
		"source.port":  float64(8080),
	}

	ev := Normalize(raw)
	if ev.ProcessPID != 999 {
		t.Errorf("expected PID 999 from float64, got %d", ev.ProcessPID)
	}
	if ev.SourcePort != 8080 {
		t.Errorf("expected port 8080 from float64, got %d", ev.SourcePort)
	}
}

func TestTranslateECS(t *testing.T) {
	raw := map[string]interface{}{
		"Image":         "C:\\Windows\\System32\\cmd.exe",
		"CommandLine":   "cmd.exe /c whoami",
		"ProcessId":     5678,
		"SourceIp":      "192.168.1.1",
		"DestinationIp": "10.0.0.1",
	}

	translated := TranslateECS(raw)
	if translated["process.executable"] != "C:\\Windows\\System32\\cmd.exe" {
		t.Errorf("expected ECS-mapped 'process.executable', got '%v'", translated["process.executable"])
	}
	if translated["process.command_line"] != "cmd.exe /c whoami" {
		t.Errorf("expected ECS-mapped 'process.command_line', got '%v'", translated["process.command_line"])
	}
	if translated["source.ip"] != "192.168.1.1" {
		t.Errorf("expected ECS-mapped 'source.ip', got '%v'", translated["source.ip"])
	}
	// Unknown keys pass through unchanged
	if _, ok := raw["Image"]; !ok {
		t.Error("original key should still exist")
	}
}

func TestFlatten(t *testing.T) {
	ev := Normalize(map[string]interface{}{
		"event.type":    "process_start",
		"event.platform": "linux",
		"process.name":  "bash",
		"severity":      "high",
		"host.hostname": "test-host",
	})

	flattened := Flatten(ev)
	if flattened.Source != "endpoint_behavior_monitor" {
		t.Errorf("expected source 'endpoint_behavior_monitor', got '%s'", flattened.Source)
	}
	if flattened.EventCategory != "process" {
		t.Errorf("expected category 'process', got '%s'", flattened.EventCategory)
	}
	if flattened.HostName != "test-host" {
		t.Errorf("expected host_name 'test-host', got '%s'", flattened.HostName)
	}
}

func TestFlattenNetworkCategory(t *testing.T) {
	ev := Normalize(map[string]interface{}{
		"event.type": "network_connect",
	})

	flattened := Flatten(ev)
	if flattened.EventCategory != "network" {
		t.Errorf("expected category 'network', got '%s'", flattened.EventCategory)
	}
}

func TestFlattenEmulationCategory(t *testing.T) {
	ev := Normalize(map[string]interface{}{
		"event.type":     "process_start",
		"event.platform": "emulator",
	})

	flattened := Flatten(ev)
	if flattened.EventCategory != "emulation" {
		t.Errorf("expected category 'emulation', got '%s'", flattened.EventCategory)
	}
}

func TestDeriveType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"process_start", "start"},
		{"network_connect", "connect"},
		{"file_create", "create"},
		{"registry_set", "set"},
		{"dns_query", "query"},
		{"simple", "simple"},
	}

	for _, tc := range tests {
		result := deriveType(tc.input)
		if result != tc.expected {
			t.Errorf("deriveType(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestTranslateAndNormalize(t *testing.T) {
	raw := map[string]interface{}{
		"Image":              "powershell.exe",
		"CommandLine":       "-enc ABC",
		"event.type":         "process_start",
		"process.parent.name": "winword.exe",
	}

	ev := TranslateAndNormalize(raw)
	if ev.ProcessExe != "powershell.exe" {
		t.Errorf("expected 'powershell.exe' from ECS mapping (process.executable), got '%s'", ev.ProcessExe)
	}
	if ev.ProcessCmdLine != "-enc ABC" {
		t.Errorf("expected '-enc ABC' from ECS mapping (process.command_line), got '%s'", ev.ProcessCmdLine)
	}
	if ev.EventType != "process_start" {
		t.Errorf("expected 'process_start', got '%s'", ev.EventType)
	}
	if ev.ParentName != "winword.exe" {
		t.Errorf("expected 'winword.exe', got '%s'", ev.ParentName)
	}
}