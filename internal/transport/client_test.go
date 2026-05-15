package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aiagentmackenzie-lang/ebm/internal/config"
	"github.com/aiagentmackenzie-lang/ebm/internal/model"
)

func TestNewClient(t *testing.T) {
	cfg := config.SIEMConfig{
		URL:          "http://localhost:8000/api/v1/ingest",
		BearerToken:  "test-token",
		TimeoutSec:   5,
	}
	_, err := New(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
}

func TestHealthCheckSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := config.SIEMConfig{
		URL:            server.URL + "/ingest",
		HealthCheckURL: server.URL + "/health",
		BearerToken:    "test-token",
		TimeoutSec:     5,
	}
	client, _ := New(cfg)

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("health check: %v", err)
	}
}

func TestHealthCheckFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := config.SIEMConfig{
		URL:            server.URL + "/ingest",
		HealthCheckURL: server.URL + "/health",
		BearerToken:    "test-token",
		TimeoutSec:     5,
	}
	client, _ := New(cfg)

	if err := client.HealthCheck(context.Background()); err == nil {
		t.Error("expected health check error")
	}
}

func TestSendSuccess(t *testing.T) {
	var receivedBody []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer token, got '%s'", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected JSON content type, got '%s'", r.Header.Get("Content-Type"))
		}
		var body []map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		receivedBody = body
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted": 1}`))
	}))
	defer server.Close()

	cfg := config.SIEMConfig{
		URL:          server.URL + "/ingest",
		BearerToken:  "test-token",
		TimeoutSec:   5,
	}
	client, _ := New(cfg)

	events := []model.Event{
		{
			EventType:   "process_start",
			ProcessName: "test.exe",
			Severity:    "info",
		},
	}

	err := client.Send(context.Background(), events)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(receivedBody) != 1 {
		t.Errorf("expected 1 event received, got %d", len(receivedBody))
	}
}

func TestSendFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := config.SIEMConfig{
		URL:          server.URL + "/ingest",
		BearerToken:  "test-token",
		TimeoutSec:   5,
	}
	client, _ := New(cfg)

	events := []model.Event{{EventType: "test"}}
	err := client.Send(context.Background(), events)
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestSendWithContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never responds
		select {}
	}))
	defer server.Close()

	cfg := config.SIEMConfig{
		URL:          server.URL + "/ingest",
		BearerToken:  "test-token",
		TimeoutSec:   30,
	}
	client, _ := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	events := []model.Event{{EventType: "test"}}
	err := client.Send(ctx, events)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}