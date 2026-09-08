package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Addr != ":8200" {
		t.Errorf("expected addr ':8200', got '%s'", cfg.Server.Addr)
	}
	if cfg.Vault.Threshold != 3 {
		t.Errorf("expected threshold 3, got %d", cfg.Vault.Threshold)
	}
	if cfg.Vault.Total != 5 {
		t.Errorf("expected total 5, got %d", cfg.Vault.Total)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.Server.Addr = ":9000"
	cfg.Save(path)

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Server.Addr != ":9000" {
		t.Errorf("expected addr ':9000', got '%s'", loaded.Server.Addr)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.json")
	if !errors.Is(err, ErrConfigNotFound) {
		t.Errorf("expected ErrConfigNotFound, got %v", err)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	os.WriteFile(path, []byte("invalid json"), 0600)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSaveConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	err := cfg.Save(path)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("config file not created")
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{"valid", func(c *Config) {}, false},
		{"threshold too low", func(c *Config) { c.Vault.Threshold = 1 }, true},
		{"total less than threshold", func(c *Config) { c.Vault.Total = 2; c.Vault.Threshold = 3 }, true},
		{"empty addr", func(c *Config) { c.Server.Addr = "" }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_Durations(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("expected read timeout 10s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Auth.TokenTTL != 24*time.Hour {
		t.Errorf("expected token TTL 24h, got %v", cfg.Auth.TokenTTL)
	}
}
