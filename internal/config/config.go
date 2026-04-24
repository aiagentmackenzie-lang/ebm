package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the agent configuration.
type Config struct {
	Agent      AgentConfig      `yaml:"agent"`
	SIEM       SIEMConfig       `yaml:"siem"`
	Collection CollectionConfig `yaml:"collection"`
	Rules      RulesConfig      `yaml:"rules"`
	Storage    StorageConfig    `yaml:"storage"`
	Emulator   EmulatorConfig   `yaml:"emulator"`
}

type AgentConfig struct {
	ID       string `yaml:"id"`
	Version  string `yaml:"version"`
	LogLevel string `yaml:"log_level"`
}

type SIEMConfig struct {
	URL                    string `yaml:"url"`
	WSURL                  string `yaml:"ws_url"`
	BearerToken            string `yaml:"bearer_token"`
	BatchSize              int    `yaml:"batch_size"`
	FlushIntervalSec       int    `yaml:"flush_interval_sec"`
	HealthCheckURL         string `yaml:"health_check_url"`
	HealthCheckIntervalSec int    `yaml:"health_check_interval_sec"`
	TimeoutSec             int    `yaml:"timeout_sec"`
}

func (s *SIEMConfig) FlushInterval() time.Duration {
	return time.Duration(s.FlushIntervalSec) * time.Second
}

func (s *SIEMConfig) HealthCheckInterval() time.Duration {
	return time.Duration(s.HealthCheckIntervalSec) * time.Second
}

func (s *SIEMConfig) Timeout() time.Duration {
	return time.Duration(s.TimeoutSec) * time.Second
}

type CollectionConfig struct {
	Enabled         bool `yaml:"enabled"`
	ProcessEvents   bool `yaml:"process_events"`
	NetworkEvents   bool `yaml:"network_events"`
	FileEvents      bool `yaml:"file_events"`
	DNSEvents       bool `yaml:"dns_events"`
	RegistryEvents  bool `yaml:"registry_events"`
	ImageLoadEvents bool `yaml:"image_load_events"`
}

type RulesConfig struct {
	Enabled           bool   `yaml:"enabled"`
	RulesDir          string `yaml:"rules_dir"`
	ReloadIntervalSec int    `yaml:"reload_interval_sec"`
}

type StorageConfig struct {
	DBPath         string `yaml:"db_path"`
	MaxSizeMB      int    `yaml:"max_size_mb"`
	RetentionHours int    `yaml:"retention_hours"`
}

type EmulatorConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Load reads and unmarshals the configuration from the given path,
// resolving environment variables embedded as ${VAR}.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	resolved := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(resolved), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) setDefaults() error {
	if c.Agent.LogLevel == "" {
		c.Agent.LogLevel = "info"
	}
	if c.Agent.Version == "" {
		c.Agent.Version = "1.0.0"
	}
	if c.Agent.ID == "" {
		id, err := os.ReadFile("agent.id")
		if err != nil {
			c.Agent.ID = generateAgentID()
			_ = os.WriteFile("agent.id", []byte(c.Agent.ID), 0o600)
		} else {
			c.Agent.ID = string(id)
		}
	}
	if c.SIEM.BatchSize == 0 {
		c.SIEM.BatchSize = 50
	}
	if c.SIEM.FlushIntervalSec == 0 {
		c.SIEM.FlushIntervalSec = 10
	}
	if c.SIEM.HealthCheckIntervalSec == 0 {
		c.SIEM.HealthCheckIntervalSec = 30
	}
	if c.SIEM.TimeoutSec == 0 {
		c.SIEM.TimeoutSec = 10
	}
	if c.Rules.RulesDir == "" {
		c.Rules.RulesDir = "./rules"
	}
	if c.Storage.DBPath == "" {
		c.Storage.DBPath = "./ebm_queue.db"
	}
	if c.Storage.MaxSizeMB == 0 {
		c.Storage.MaxSizeMB = 100
	}
	if c.Storage.RetentionHours == 0 {
		c.Storage.RetentionHours = 72
	}
	return nil
}

func generateAgentID() string {
	return fmt.Sprintf("ebm-agent-%d", time.Now().UnixNano())
}
