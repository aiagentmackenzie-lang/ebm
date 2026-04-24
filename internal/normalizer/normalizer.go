package normalizer

import (
	"time"

	"github.com/aiagentmackenzie-lang/ebm/internal/model"
)

// Normalize maps a raw platform event into the EDR Core Schema.
func Normalize(raw map[string]interface{}) model.Event {
	ev := model.Event{
		Timestamp:     time.Now().UTC(),
		EventType:     stringValue(raw, "event.type", "unknown"),
		EventPlatform: stringValue(raw, "event.platform", "unknown"),
		EventProvider: stringValue(raw, "event.provider", "unknown"),
		HostHostname:  stringValue(raw, "host.hostname", ""),
		HostOSType:    stringValue(raw, "host.os.type", ""),
		HostOSVersion: stringValue(raw, "host.os.version", ""),
		UserName:      stringValue(raw, "user.name", ""),
		UserID:        stringValue(raw, "user.id", ""),
		ProcessPID:    intValue(raw, "process.pid", 0),
		ProcessName:   stringValue(raw, "process.name", ""),
		ProcessCmdLine: stringValue(raw, "process.command_line", ""),
		ProcessExe:    stringValue(raw, "process.executable", ""),
		ProcessHashSHA: stringValue(raw, "process.hash.sha256", ""),
		ParentPID:     intValue(raw, "process.parent.pid", 0),
		ParentName:    stringValue(raw, "process.parent.name", ""),
		ParentCmdLine: stringValue(raw, "process.parent.command_line", ""),
		NetworkDirection: stringValue(raw, "network.direction", ""),
		NetworkTransport: stringValue(raw, "network.transport", ""),
		SourceIP:      stringValue(raw, "source.ip", ""),
		SourcePort:    intValue(raw, "source.port", 0),
		DestIP:        stringValue(raw, "destination.ip", ""),
		DestPort:      intValue(raw, "destination.port", 0),
		DestDomain:    stringValue(raw, "destination.domain", ""),
		FilePath:      stringValue(raw, "file.path", ""),
		RegistryPath:  stringValue(raw, "registry.path", ""),
		Severity:      stringValue(raw, "severity", "info"),
		RawData:       raw,
	}

	// Map array fields
	if v, ok := raw["mitre.technique_id"].([]string); ok {
		ev.MITRETIDs = v
	}
	if v, ok := raw["mitre.tactic"].(string); ok {
		ev.MITRETactic = v
	}

	return ev
}

func stringValue(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}

func intValue(m map[string]interface{}, key string, fallback int) int {
	if v, ok := m[key].(int); ok {
		return v
	}
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return fallback
}
