package engine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/raphael/ebm/internal/model"
	"gopkg.in/yaml.v3"
)

// Engine evaluates detection rules against incoming events.
type Engine struct {
	rules []Rule
}

// Rule represents a simplified detection rule.
type Rule struct {
	ID          string                 `yaml:"id"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	MITRE       MITRE                  `yaml:"mitre"`
	Severity    string                 `yaml:"severity"`
	Condition   map[string]interface{} `yaml:"condition"`
}

// MITRE holds technique and tactic info.
type MITRE struct {
	Technique string `yaml:"technique"`
	Tactic    string `yaml:"tactic"`
}

// New loads rules from the configured directory.
func New(rulesDir string) (*Engine, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, err
	}

	var rules []Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(rulesDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("read rule file", "path", path, "error", err)
			continue
		}

		var rule Rule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			slog.Warn("unmarshal rule file", "path", path, "error", err)
			continue
		}
		rules = append(rules, rule)
	}

	slog.Info("detection engine loaded", "rules", len(rules))
	return &Engine{rules: rules}, nil
}

// Evaluate runs all rules against the event and returns triggered alerts.
func (e *Engine) Evaluate(ev model.Event) []model.Alert {
	var alerts []model.Alert
	for _, rule := range e.rules {
		if matchCondition(rule.Condition, ev) {
			alerts = append(alerts, model.Alert{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				MITRETIDs:   []string{rule.MITRE.Technique},
				MITRETactic: rule.MITRE.Tactic,
				Evidence:    ev,
			})
		}
	}
	return alerts
}

// Rules returns the loaded detection rules for inspection.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

var eventFieldMap = map[string]func(ev model.Event) interface{}{
	"event.type":                  func(ev model.Event) interface{} { return ev.EventType },
	"event.platform":              func(ev model.Event) interface{} { return ev.EventPlatform },
	"event.provider":              func(ev model.Event) interface{} { return ev.EventProvider },
	"host.hostname":               func(ev model.Event) interface{} { return ev.HostHostname },
	"user.name":                   func(ev model.Event) interface{} { return ev.UserName },
	"user.id":                     func(ev model.Event) interface{} { return ev.UserID },
	"process.pid":                 func(ev model.Event) interface{} { return ev.ProcessPID },
	"process.name":                func(ev model.Event) interface{} { return ev.ProcessName },
	"process.command_line":        func(ev model.Event) interface{} { return ev.ProcessCmdLine },
	"process.executable":          func(ev model.Event) interface{} { return ev.ProcessExe },
	"process.hash.sha256":         func(ev model.Event) interface{} { return ev.ProcessHashSHA },
	"process.parent.pid":          func(ev model.Event) interface{} { return ev.ParentPID },
	"process.parent.name":         func(ev model.Event) interface{} { return ev.ParentName },
	"process.parent.command_line": func(ev model.Event) interface{} { return ev.ParentCmdLine },
	"network.direction":           func(ev model.Event) interface{} { return ev.NetworkDirection },
	"network.transport":           func(ev model.Event) interface{} { return ev.NetworkTransport },
	"source.ip":                   func(ev model.Event) interface{} { return ev.SourceIP },
	"source.port":                 func(ev model.Event) interface{} { return ev.SourcePort },
	"destination.ip":              func(ev model.Event) interface{} { return ev.DestIP },
	"destination.port":            func(ev model.Event) interface{} { return ev.DestPort },
	"destination.domain":          func(ev model.Event) interface{} { return ev.DestDomain },
	"file.path":                   func(ev model.Event) interface{} { return ev.FilePath },
	"registry.path":               func(ev model.Event) interface{} { return ev.RegistryPath },
	"severity":                    func(ev model.Event) interface{} { return ev.Severity },
}

// getField resolves a field from the event, checking both native fields and RawData.
func getField(ev model.Event, key string) (interface{}, bool) {
	if fn, ok := eventFieldMap[key]; ok {
		return fn(ev), true
	}
	if ev.RawData != nil {
		if v, ok := ev.RawData[key]; ok {
			return v, true
		}
	}
	return nil, false
}

// matchCondition traverses the rule condition map. All top-level keys must satisfy.
// A key suffixed with |modifier forces the modifier logic.
func matchCondition(cond map[string]interface{}, ev model.Event) bool {
	for key, expected := range cond {
		modifier := ""
		fieldKey := key
		if idx := strings.Index(key, "|"); idx > 0 {
			fieldKey = key[:idx]
			modifier = strings.ToLower(key[idx+1:])
		}
		actual, ok := getField(ev, fieldKey)
		if !ok {
			return false
		}
		if !valueMatches(expected, actual, modifier) {
			return false
		}
	}
	return true
}

func valueMatches(expected, actual interface{}, modifier string) bool {
	if expected == nil {
		return actual == nil
	}

	switch modifier {
	case "contains":
		exp, ok1 := expected.(string)
		act, ok2 := actual.(string)
		return ok1 && ok2 && strings.Contains(act, exp)
	case "startswith":
		exp, ok1 := expected.(string)
		act, ok2 := actual.(string)
		return ok1 && ok2 && strings.HasPrefix(act, exp)
	case "endswith":
		exp, ok1 := expected.(string)
		act, ok2 := actual.(string)
		return ok1 && ok2 && strings.HasSuffix(act, exp)
	case "not_in":
		return !orMatches(expected, actual, "")
	default:
		return orMatches(expected, actual, modifier)
	}
}

func orMatches(expected, actual interface{}, modifier string) bool {
	switch exp := expected.(type) {
	case string:
		act, ok := actual.(string)
		return ok && strings.EqualFold(act, exp)
	case int:
		act, ok := actual.(int)
		return ok && act == exp
	case []interface{}:
		for _, item := range exp {
			if valueMatches(item, actual, modifier) {
				return true
			}
		}
		return false
	case []string:
		act, ok := actual.(string)
		if !ok {
			return false
		}
		for _, item := range exp {
			if strings.EqualFold(act, item) {
				return true
			}
		}
		return false
	default:
		return fmt.Sprintf("%v", expected) == fmt.Sprintf("%v", actual)
	}
}
