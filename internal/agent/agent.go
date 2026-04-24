package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/raphael/ebm/internal/collector"
	"github.com/raphael/ebm/internal/config"
	"github.com/raphael/ebm/internal/engine"
	"github.com/raphael/ebm/internal/model"
	"github.com/raphael/ebm/internal/normalizer"
	"github.com/raphael/ebm/internal/storage"
	"github.com/raphael/ebm/internal/transport"
)

// Agent orchestrates collectors, normalizer, rule engine, and transport.
type Agent struct {
	cfg        *config.Config
	collector  collector.Collector
	storage    *storage.SQLiteQueue
	client     *transport.Client
	engine     *engine.Engine
	wg         sync.WaitGroup
	stopCh     chan struct{}
	rawCh      chan map[string]interface{}
}

// New initializes the agent based on the provided configuration path.
func New(configPath string) (*Agent, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	store, err := storage.New(cfg.Storage.DBPath)
	if err != nil {
		return nil, fmt.Errorf("initialize storage: %w", err)
	}

	client, err := transport.New(cfg.SIEM)
	if err != nil {
		return nil, fmt.Errorf("initialize transport: %w", err)
	}

	eng, err := engine.New(cfg.Rules.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("initialize rule engine: %w", err)
	}

	coll, err := collector.New()
	if err != nil {
		return nil, fmt.Errorf("initialize collector: %w", err)
	}

	return &Agent{
		cfg:       cfg,
		collector: coll,
		storage:   store,
		client:    client,
		engine:    eng,
		stopCh:    make(chan struct{}),
		rawCh:     make(chan map[string]interface{}, 256),
	}, nil
}

// Start begins collection and processing loops.
func (a *Agent) Start(ctx context.Context) error {
	slog.Info("agent starting", "version", a.cfg.Agent.Version, "id", a.cfg.Agent.ID)

	// Start collector -> raw events
	go func() {
		if err := a.collector.Start(ctx, a.rawCh); err != nil {
			slog.Error("collector stopped", "error", err)
		}
	}()

	// Start normalizer + rule engine + enqueue worker
	a.wg.Add(1)
	go a.ruleWorker(ctx)

	// Start transport worker
	a.wg.Add(1)
	go a.transportWorker(ctx)

	slog.Info("agent started")
	return nil
}

// Stop gracefully shuts down all agent components.
func (a *Agent) Stop() error {
	close(a.stopCh)
	a.wg.Wait()

	// Final drain attempt
	if err := a.flush(); err != nil {
		slog.Error("final flush failed", "error", err)
	}

	if err := a.storage.Close(); err != nil {
		return fmt.Errorf("close storage: %w", err)
	}

	slog.Info("agent stopped")
	return nil
}

func (a *Agent) ruleWorker(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ctx.Done():
			return
		case raw := <-a.rawCh:
			// Translate ECS then normalize to Event
			ev := normalizer.TranslateAndNormalize(raw)
			alerts := a.engine.Evaluate(ev)
			for _, alert := range alerts {
				// Queue alert as event for transport
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
				if err := a.storage.Enqueue(alertEvent); err != nil {
					slog.Error("enqueue alert event", "error", err)
				}
			}
			// Queue normalized event for transport
			if err := a.storage.Enqueue(ev); err != nil {
				slog.Error("enqueue event", "error", err)
			}
		}
	}
}

func (a *Agent) transportWorker(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.SIEM.FlushInterval())
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.flush(); err != nil {
				slog.Error("flush events", "error", err)
			}
		}
	}
}

func (a *Agent) flush() error {
	if err := a.client.HealthCheck(context.Background()); err != nil {
		slog.Warn("siem health check failed, deferring flush", "error", err)
		return nil
	}

	events, err := a.storage.Dequeue(a.cfg.SIEM.BatchSize)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	if err := a.client.Send(events); err != nil {
		if rollbackErr := a.storage.Requeue(events); rollbackErr != nil {
			return fmt.Errorf("send failed: %w; rollback also failed: %v", err, rollbackErr)
		}
		return err
	}

	return a.storage.MarkSent(events)
}

// InjectEvent pushes a raw event into the agent pipeline.
func (a *Agent) InjectEvent(raw map[string]interface{}) {
	select {
	case a.rawCh <- raw:
	default:
		slog.Warn("agent raw channel full, dropping injected event")
	}
}

// ListRules returns the currently loaded detection rules.
func (a *Agent) ListRules() ([]engine.Rule, error) {
	return a.engine.Rules(), nil
}
