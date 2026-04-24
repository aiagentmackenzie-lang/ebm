package normalizer

import (
	"github.com/aiagentmackenzie-lang/ebm/internal/model"
)

// Flatten converts an internal EDR Core Schema Event into the flat
// SecurityScarletAI IngestEvent format.
func Flatten(e model.Event) model.IngestEvent {
	return model.IngestEvent{
		Timestamp:     e.Timestamp,
		HostName:      e.HostHostname,
		Source:        "endpoint_behavior_monitor",
		EventCategory: deriveCategory(e.EventType, e.EventPlatform),
		EventType:     deriveType(e.EventType),
		EventAction:   e.EventType,
		RawData:       e.RawData,
		UserName:      e.UserName,
		ProcessName:   e.ProcessName,
		ProcessPID:    e.ProcessPID,
		SourceIP:      e.SourceIP,
		DestIP:        e.DestIP,
		DestPort:      e.DestPort,
		FilePath:      e.FilePath,
		FileHash:      e.ProcessHashSHA,
		Severity:      e.Severity,
	}
}

func deriveCategory(eventType string, platform string) string {
	if platform == "emulator" {
		return "emulation"
	}
	switch eventType {
	case "process_start", "process_stop", "process_access":
		return "process"
	case "network_connect", "dns_query":
		return "network"
	case "file_create", "file_modify", "file_delete":
		return "file"
	case "registry_set", "registry_create", "registry_delete":
		return "registry"
	case "image_load":
		return "image"
	default:
		return "general"
	}
}

func deriveType(eventType string) string {
	parts := splitEventType(eventType)
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return eventType
}

func splitEventType(eventType string) []string {
	// simple split by underscore
	var out []string
	var last int
	for i, r := range eventType {
		if r == '_' {
			out = append(out, eventType[last:i])
			last = i + 1
		}
	}
	out = append(out, eventType[last:])
	return out
}
