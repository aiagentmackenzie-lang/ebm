package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aiagentmackenzie-lang/ebm/internal/agent"
	"github.com/aiagentmackenzie-lang/ebm/internal/config"
	"github.com/aiagentmackenzie-lang/ebm/internal/emulator"
	"github.com/aiagentmackenzie-lang/ebm/internal/engine"
	"github.com/aiagentmackenzie-lang/ebm/internal/model"
	"github.com/aiagentmackenzie-lang/ebm/internal/normalizer"
	"github.com/aiagentmackenzie-lang/ebm/internal/transport"
)

var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	emulateCmd = flag.Bool("emulate", false, "Run adversary emulation CLI")
	technique  = flag.String("technique", "", "Technique ID to emulate (used with -emulate)")
	scenario   = flag.String("scenario", "", "Scenario name to emulate (used with -emulate)")
	listRules  = flag.Bool("list-rules", false, "List loaded detection rules")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if *emulateCmd {
		if err := runEmulation(ctx); err != nil {
			slog.Error("emulation failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if *listRules {
		if err := listDetectionRules(); err != nil {
			slog.Error("list rules failed", "error", err)
			os.Exit(1)
		}
		return
	}

	ag, err := agent.New(*configPath)
	if err != nil {
		slog.Error("agent initialization failed", "error", err)
		os.Exit(1)
	}

	if err := ag.Start(ctx); err != nil {
		slog.Error("agent start failed", "error", err)
		os.Exit(1)
	}

	<-ctx.Done()
	slog.Info("shutting down")
	if err := ag.Stop(); err != nil {
		slog.Error("agent stop failed", "error", err)
	}
}

func runEmulation(ctx context.Context) error {
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Initialize rule engine for emulation
	eng, err := engine.New(cfg.Rules.RulesDir)
	if err != nil {
		return fmt.Errorf("init engine: %w", err)
	}

	// Initialize transport client
	client, err := transport.New(cfg.SIEM)
	if err != nil {
		return fmt.Errorf("init transport: %w", err)
	}

	// Emitter: normalize, evaluate, and send
	emitFn := func(raw map[string]interface{}) {
		ev := normalizer.TranslateAndNormalize(raw)
		alerts := eng.Evaluate(ev)
		var batch []model.Event
		for _, alert := range alerts {
			alertEvent := model.Event{
				Timestamp:      alert.Timestamp,
				EventType:      "alert",
				HostHostname:   ev.HostHostname,
				Severity:       alert.Severity,
				ProcessName:    ev.ProcessName,
				ProcessCmdLine: ev.ProcessCmdLine,
				RawData: map[string]interface{}{
					"rule_id":            alert.RuleID,
					"rule_name":          alert.RuleName,
					"description":        alert.Description,
					"mitre.technique_id": alert.MITRETIDs,
					"mitre.tactic":       alert.MITRETactic,
				},
			}
			batch = append(batch, alertEvent)
		}
		batch = append(batch, ev)
		if err := client.Send(batch); err != nil {
			slog.Error("emulation send failed", "error", err)
		}
	}

	emul := emulator.New(emitFn)
	if *scenario != "" {
		fmt.Printf("Running scenario %s...\n", *scenario)
		if err := emul.RunScenario(*scenario); err != nil {
			return err
		}
		// Give time for transport to complete before process exits
		time.Sleep(2 * time.Second)
		return nil
	}
	if *technique == "" {
		return fmt.Errorf("--technique or --scenario required")
	}
	fmt.Printf("Emulating technique %s...\n", *technique)
	if err := emul.Run(ctx, *technique, ""); err != nil {
		return err
	}
	// Give time for transport to complete before process exits
	time.Sleep(2 * time.Second)
	return nil
}

func listDetectionRules() error {
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	eng, err := engine.New(cfg.Rules.RulesDir)
	if err != nil {
		return fmt.Errorf("load engine: %w", err)
	}
	for _, r := range eng.Rules() {
		fmt.Printf("%s | %s | %s | Severity: %s | MITRE: %s (%s)\n",
			r.ID, r.Name, r.Description, r.Severity, r.MITRE.Technique, r.MITRE.Tactic)
	}
	return nil
}
