package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrConfigNotFound = errors.New("config: configuration file not found")
	ErrInvalidConfig  = errors.New("config: invalid configuration")
)

type Config struct {
	Server  ServerConfig  `json:"server"`
	Vault   VaultConfig   `json:"vault"`
	Storage StorageConfig `json:"storage"`
	Audit   AuditConfig   `json:"audit"`
	Auth    AuthConfig    `json:"auth"`
}

type ServerConfig struct {
	Addr         string        `json:"addr"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

type VaultConfig struct {
	Threshold int    `json:"threshold"`
	Total     int    `json:"total"`
	DataDir   string `json:"data_dir"`
}

type StorageConfig struct {
	Type string `json:"type"` // "file" or "sqlite"
	Dir  string `json:"dir"`
}

type AuditConfig struct {
	Enabled bool   `json:"enabled"`
	File    string `json:"file"`
	Key     string `json:"key"`
}

type AuthConfig struct {
	Enabled    bool          `json:"enabled"`
	TokenTTL   time.Duration `json:"token_ttl"`
	AdminToken string        `json:"admin_token,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Addr:         ":8200",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  30 * time.Second,
		},
		Vault: VaultConfig{
			Threshold: 3,
			Total:     5,
			DataDir:   "./vault-data",
		},
		Storage: StorageConfig{
			Type: "file",
			Dir:  "./vault-data/storage",
		},
		Audit: AuditConfig{
			Enabled: true,
			File:    "./vault-data/audit.log",
			Key:     "", // must be set
		},
		Auth: AuthConfig{
			Enabled:  true,
			TokenTTL: 24 * time.Hour,
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("config: failed to read file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: failed to parse file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("config: failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("config: failed to write file: %w", err)
	}

	return nil
}

func (c *Config) Validate() error {
	if c.Vault.Threshold < 2 {
		return fmt.Errorf("%w: threshold must be >= 2", ErrInvalidConfig)
	}
	if c.Vault.Total < c.Vault.Threshold {
		return fmt.Errorf("%w: total must be >= threshold", ErrInvalidConfig)
	}
	if c.Server.Addr == "" {
		return fmt.Errorf("%w: server address is required", ErrInvalidConfig)
	}
	return nil
}
