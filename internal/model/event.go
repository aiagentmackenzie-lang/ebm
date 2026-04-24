package model

import (
	"encoding/json"
	"time"
)

// Event is the internal normalized endpoint event (EDR Core Schema).
type Event struct {
	ID              int64               `json:"id"`
	Timestamp       time.Time           `json:"@timestamp"`
	EventType       string              `json:"event.type"`
	EventPlatform   string              `json:"event.platform"`
	EventProvider   string              `json:"event.provider"`
	HostHostname    string              `json:"host.hostname"`
	HostOSType      string              `json:"host.os.type"`
	HostOSVersion   string              `json:"host.os.version"`
	HostIPs         []string            `json:"host.ip"`
	AgentID         string              `json:"agent.id"`
	AgentVersion    string              `json:"agent.version"`
	UserName        string              `json:"user.name"`
	UserID          string              `json:"user.id"`
	ProcessPID      int                 `json:"process.pid"`
	ProcessName     string              `json:"process.name"`
	ProcessCmdLine  string              `json:"process.command_line"`
	ProcessExe      string              `json:"process.executable"`
	ProcessHashSHA  string              `json:"process.hash.sha256"`
	ParentPID       int                 `json:"process.parent.pid"`
	ParentName      string              `json:"process.parent.name"`
	ParentCmdLine   string              `json:"process.parent.command_line"`
	NetworkDirection string             `json:"network.direction"`
	NetworkTransport string             `json:"network.transport"`
	SourceIP        string              `json:"source.ip"`
	SourcePort      int                 `json:"source.port"`
	DestIP          string              `json:"destination.ip"`
	DestPort        int                 `json:"destination.port"`
	DestDomain      string              `json:"destination.domain"`
	FilePath        string              `json:"file.path"`
	RegistryPath    string              `json:"registry.path"`
	MITRETIDs       []string            `json:"mitre.technique_id"`
	MITRETactic     string              `json:"mitre.tactic"`
	Severity        string              `json:"severity"`
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
}

// IngestEvent is the flattened schema for SecurityScarletAI.
type IngestEvent struct {
	Timestamp       time.Time           `json:"@timestamp"`
	HostName        string              `json:"host_name"`
	Source          string              `json:"source"`
	EventCategory   string              `json:"event_category"`
	EventType       string              `json:"event_type"`
	EventAction     string              `json:"event_action,omitempty"`
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
	UserName        string              `json:"user_name,omitempty"`
	ProcessName     string              `json:"process_name,omitempty"`
	ProcessPID      int                 `json:"process_pid,omitempty"`
	SourceIP        string              `json:"source_ip,omitempty"`
	DestIP          string              `json:"destination_ip,omitempty"`
	DestPort        int                 `json:"destination_port,omitempty"`
	FilePath        string              `json:"file_path,omitempty"`
	FileHash        string              `json:"file_hash,omitempty"`
	Severity        string              `json:"severity"`
}

// ToJSON serializes the event to JSON.
func (e Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// Alert represents a triggered detection rule.
type Alert struct {
	ID              string     `json:"id"`
	RuleID          string     `json:"rule_id"`
	RuleName        string     `json:"rule_name"`
	Timestamp       time.Time  `json:"@timestamp"`
	Severity        string     `json:"severity"`
	MITRETIDs       []string   `json:"mitre.technique_id"`
	MITRETactic     string     `json:"mitre.tactic"`
	Evidence        Event      `json:"evidence"`
	Description     string     `json:"description"`
}
