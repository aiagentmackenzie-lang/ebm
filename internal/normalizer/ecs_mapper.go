package normalizer

// ECSMap provides simple field-name mappings from platform-native conventions
// to Elastic Common Schema names used internally by the EDR Core Schema.
// These are used during the first normalization pass (pre-Event construction).

var ECSMap = map[string]string{
	// Windows / Sysmon
	"EventID":           "event.id",
	"Image":               "process.executable",
	"CommandLine":         "process.command_line",
	"CurrentDirectory":    "process.working_directory",
	"User":                "user.name",
	"LogonGuid":           "user.id",
	"ProcessGuid":         "process.guid",
	"ProcessId":           "process.pid",
	"ParentProcessGuid":   "process.parent.guid",
	"ParentProcessId":     "process.parent.pid",
	"ParentImage":         "process.parent.executable",
	"ParentCommandLine":   "process.parent.command_line",
	"TargetObject":        "registry.path",
	"Details":             "registry.value_data",
	"DestinationHostname": "destination.domain",
	"DestinationIp":       "destination.ip",
	"DestinationPort":     "destination.port",
	"SourceIp":            "source.ip",
	"SourcePort":          "source.port",
	"Protocol":            "network.transport",
	"ImageLoaded":         "library.path",

	// Linux / eBPF / auditd
	"exe":  "process.executable",
	"comm": "process.name",
	"pid":  "process.pid",
	"ppid": "process.parent.pid",
	"uid":  "user.id",
	"saddr": "destination.ip",
	"sport": "source.port",
	"dport": "destination.port",

	// macOS / ESF
	"process.path":      "process.executable",
	"process.pid":       "process.pid",
	"process.ppid":      "process.parent.pid",
	"process.uid":       "user.id",
	"file.destination":  "file.path",
}

// TranslateECS renames raw event keys to ECS-style keys when feasible.
func TranslateECS(raw map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if ecsKey, ok := ECSMap[k]; ok {
			out[ecsKey] = v
		} else {
			out[k] = v
		}
	}
	return out
}
