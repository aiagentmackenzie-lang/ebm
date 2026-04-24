package engine

import (
	"testing"
	"time"

	"github.com/raphael/ebm/internal/model"
)

func TestMatchCondition(t *testing.T) {
	ev := model.Event{
		Timestamp:      time.Now(),
		EventType:      "process_start",
		EventPlatform:  "linux",
		ProcessName:    "powershell.exe",
		ProcessCmdLine: "powershell.exe -nop",
		ParentName:     "winword.exe",
		Severity:       "high",
		RawData: map[string]interface{}{
			"target.process.name": "lsass.exe",
			"granted_access":      "0x1010",
		},
	}

	// Exact match
	if !matchCondition(map[string]interface{}{
		"event.type": "process_start",
	}, ev) {
		t.Error("expected exact match")
	}

	// OR array match
	if !matchCondition(map[string]interface{}{
		"process.name": []string{"cmd.exe", "powershell.exe"},
	}, ev) {
		t.Error("expected OR array match")
	}

	// contains modifier
	if !matchCondition(map[string]interface{}{
		"process.command_line|contains": "-nop",
	}, ev) {
		t.Error("expected contains match")
	}

	// startswith
	if !matchCondition(map[string]interface{}{
		"process.name|startswith": "power",
	}, ev) {
		t.Error("expected startswith match")
	}

	// endswith
	if !matchCondition(map[string]interface{}{
		"process.name|endswith": ".exe",
	}, ev) {
		t.Error("expected endswith match")
	}

	// RawData field resolution
	if !matchCondition(map[string]interface{}{
		"target.process.name": "lsass.exe",
	}, ev) {
		t.Error("expected rawdata field match")
	}

	// Mismatch
	if matchCondition(map[string]interface{}{
		"event.type": "network_connect",
	}, ev) {
		t.Error("expected mismatch")
	}
}

func TestEngineEvaluate(t *testing.T) {
	rules := []Rule{
		{
			ID:       "test-001",
			Name:     "OfficeSpawn",
			Severity: "high",
			Condition: map[string]interface{}{
				"event.type":          "process_start",
				"process.parent.name": []string{"winword.exe", "excel.exe"},
				"process.name":        []string{"powershell.exe", "cmd.exe"},
			},
		},
	}
	eng := &Engine{rules: rules}

	matched := eng.Evaluate(model.Event{
		EventType:  "process_start",
		ParentName: "winword.exe",
		ProcessName: "powershell.exe",
	})
	if len(matched) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(matched))
	}
	if matched[0].RuleID != "test-001" {
		t.Errorf("expected rule id test-001, got %s", matched[0].RuleID)
	}
}
