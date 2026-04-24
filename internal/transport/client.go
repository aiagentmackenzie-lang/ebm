package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/raphael/ebm/internal/config"
	"github.com/raphael/ebm/internal/model"
	"github.com/raphael/ebm/internal/normalizer"
)

// Client sends events to SecurityScarletAI.
type Client struct {
	cfg        config.SIEMConfig
	httpClient *http.Client
}

// New creates a transport client configured for the SIEM.
func New(siemCfg config.SIEMConfig) (*Client, error) {
	return &Client{
		cfg: siemCfg,
		httpClient: &http.Client{
			Timeout: siemCfg.Timeout(),
		},
	}, nil
}

// HealthCheck pings the SIEM health endpoint.
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.HealthCheckURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return nil
}

// Send transmits a batch of events as a JSON array.
func (c *Client) Send(events []model.Event) error {
	var payload []model.IngestEvent
	for _, ev := range events {
		payload = append(payload, normalizer.Flatten(ev))
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal ingest payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.BearerToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("siem returned %d", resp.StatusCode)
	}

	slog.Info("sent events to SIEM", "count", len(events))
	return nil
}
