package engine

import (
	"os"
	"testing"
	"time"

	"github.com/aiagentmackenzie-lang/ebm/internal/model"
	"gopkg.in/yaml.v3"
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

	// not_in modifier
	if !matchCondition(map[string]interface{}{
		"process.name|not_in": []string{"cmd.exe", "bash.exe"},
	}, ev) {
		t.Error("expected not_in match")
	}

	// not_in modifier — should fail when value IS in list
	if matchCondition(map[string]interface{}{
		"process.name|not_in": []string{"powershell.exe", "cmd.exe"},
	}, ev) {
		t.Error("expected not_in to reject value in list")
	}
}

func TestMatchConditionArrayKey(t *testing.T) {
	ev := model.Event{
		Timestamp:     time.Now(),
		EventType:     "registry_set",
		RegistryPath:  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`,
		ProcessName:   "cmd.exe",
		Severity:      "high",
	}

	// Array condition key: event.type should match "registry_set" OR "registry_create"
	if !matchCondition(map[string]interface{}{
		"event.type": []interface{}{"registry_set", "registry_create"},
	}, ev) {
		t.Error("expected array condition key to match")
	}

	// Array condition key: should NOT match when value not in list
	if matchCondition(map[string]interface{}{
		"event.type": []interface{}{"process_start", "network_connect"},
	}, ev) {
		t.Error("expected array condition key to NOT match")
	}
}

func TestMatchConditionCIDR(t *testing.T) {
	ev := model.Event{
		Timestamp:   time.Now(),
		EventType:   "network_connect",
		DestIP:      "192.168.1.100",
		Severity:    "medium",
	}

	// CIDR match
	if !matchCondition(map[string]interface{}{
		"destination.ip|cidr": "192.168.1.0/24",
	}, ev) {
		t.Error("expected CIDR match")
	}

	// CIDR non-match
	if matchCondition(map[string]interface{}{
		"destination.ip|cidr": "10.0.0.0/8",
	}, ev) {
		t.Error("expected CIDR non-match")
	}

	// not_cidr match
	if !matchCondition(map[string]interface{}{
		"destination.ip|not_cidr": "10.0.0.0/8",
	}, ev) {
		t.Error("expected not_cidr match (IP is NOT in this range)")
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
		EventType:   "process_start",
		ParentName:  "winword.exe",
		ProcessName: "powershell.exe",
	})
	if len(matched) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(matched))
	}
	if matched[0].RuleID != "test-001" {
		t.Errorf("expected rule id test-001, got %s", matched[0].RuleID)
	}
}

func TestEngineEvaluateNoMatch(t *testing.T) {
	rules := []Rule{
		{
			ID:       "test-002",
			Name:     "Beacon",
			Severity: "medium",
			Condition: map[string]interface{}{
				"event.type": "network_connect",
			},
		},
	}
	eng := &Engine{rules: rules}

	matched := eng.Evaluate(model.Event{
		EventType: "process_start",
	})
	if len(matched) != 0 {
		t.Errorf("expected 0 alerts for non-matching event, got %d", len(matched))
	}
}

func TestEngineEvaluateEmptyRules(t *testing.T) {
	eng := &Engine{rules: []Rule{}}
	matched := eng.Evaluate(model.Event{EventType: "anything"})
	if len(matched) != 0 {
		t.Errorf("expected 0 alerts with empty rules, got %d", len(matched))
	}
}

func TestEngineEvaluateReturnsNonNilSlice(t *testing.T) {
	eng := &Engine{rules: []Rule{}}
	matched := eng.Evaluate(model.Event{EventType: "anything"})
	if matched == nil {
		t.Error("expected non-nil slice, got nil")
	}
}

func TestNewEngine(t *testing.T) {
	// Create temp rules dir
	dir, err := os.MkdirTemp("", "ebm_rules_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Write a test rule
	rule := Rule{
		ID:          "test-rule-001",
		Name:        "Test Rule",
		Description: "A test rule",
		Severity:    "high",
		Condition: map[string]interface{}{
			"event.type": "process_start",
		},
		MITRE: MITRE{
			Technique: "T1059.001",
			Tactic:    "Execution",
		},
	}
	data, _ := yaml.Marshal(rule)
	os.WriteFile(dir+"/test.yaml", data, 0644)

	eng, err := New(dir)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if len(eng.Rules()) != 1 {
		t.Errorf("expected 1 rule, got %d", len(eng.Rules()))
	}
}

func TestNewEngineEmptyDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "ebm_rules_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	eng, err := New(dir)
	if err != nil {
		t.Fatalf("new engine empty dir: %v", err)
	}
	if len(eng.Rules()) != 0 {
		t.Errorf("expected 0 rules, got %d", len(eng.Rules()))
	}
}

func TestNewEngineMissingDir(t *testing.T) {
	_, err := New("/nonexistent/path/rules")
	if err == nil {
		t.Error("expected error for missing rules dir")
	}
}

func TestNewEngineSkipsInvalidYAML(t *testing.T) {
	dir, err := os.MkdirTemp("", "ebm_rules_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Write invalid YAML
	os.WriteFile(dir+"/bad.yaml", []byte("invalid: [broken yaml"), 0644)

	eng, err := New(dir)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if len(eng.Rules()) != 0 {
		t.Errorf("expected 0 rules from invalid YAML, got %d", len(eng.Rules()))
	}
}

func TestRulesReturnsCopy(t *testing.T) {
	eng := &Engine{rules: []Rule{{ID: "r1"}}}
	r := eng.Rules()
	r[0].ID = "modified"
	if eng.Rules()[0].ID != "r1" {
		t.Error("Rules() should return a copy, not a reference")
	}
}

func TestValueMatchesFloat64(t *testing.T) {
	ev := model.Event{
		EventType:  "test",
		SourcePort: 8080,
	}

	// YAML may unmarshal numbers as float64 in some contexts
	if !valueMatches(float64(8080), ev.SourcePort, "") {
		t.Error("expected float64 8080 to match int 8080")
	}
}