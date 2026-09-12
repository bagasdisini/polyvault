package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bagasdisini/polyvault/internal/api"
	"github.com/bagasdisini/polyvault/internal/config"
	"github.com/bagasdisini/polyvault/pkg/audit"
	"github.com/bagasdisini/polyvault/pkg/auth"
	"github.com/bagasdisini/polyvault/pkg/shamir"
	"github.com/bagasdisini/polyvault/pkg/storage"
	"github.com/bagasdisini/polyvault/pkg/transit"
	"github.com/bagasdisini/polyvault/pkg/vault"
)

// App is the main application that wires all components.
type App struct {
	Config  *config.Config
	Vault   *vault.Vault
	Auth    *auth.Authenticator
	Transit *transit.Transit
	Audit   *audit.Logger
	Logger  *slog.Logger
	Store   *storage.FileStore
}

// New creates a new application from configuration.
func New(cfg *config.Config) (*App, error) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create data directory
	if err := os.MkdirAll(cfg.Vault.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create file storage
	store, err := storage.NewFileStore(filepath.Join(cfg.Vault.DataDir, "storage"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create vault with storage backend
	v, err := vault.New(vault.Config{
		Threshold: cfg.Vault.Threshold,
		Total:     cfg.Vault.Total,
		Storage:   store,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vault: %w", err)
	}

	// Create authenticator
	authenticator := auth.New()

	// Create transit engine
	transitEngine := transit.New()

	// Create audit logger
	auditPath := filepath.Join(cfg.Vault.DataDir, "audit.log")
	auditFile, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	auditLogger := audit.New([]byte("polyvault-audit-key"), auditFile)

	return &App{
		Config:  cfg,
		Vault:   v,
		Auth:    authenticator,
		Transit: transitEngine,
		Audit:   auditLogger,
		Logger:  logger,
		Store:   store,
	}, nil
}

// StartServer starts the HTTP API server.
func (a *App) StartServer() error {
	server := api.New(api.ServerConfig{
		Vault:   a.Vault,
		Auth:    a.Auth,
		Transit: a.Transit,
		Audit:   a.Audit,
		Logger:  a.Logger,
		Addr:    a.Config.Server.Addr,
	})
	a.Logger.Info("starting server", "addr", a.Config.Server.Addr)
	return server.Start()
}

// InitVault initializes a new vault and returns the unseal shares.
func (a *App) InitVault() ([]shamir.Share, error) {
	shares, err := a.Vault.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize vault: %w", err)
	}

	a.Audit.Log(audit.EventUnseal, "system", "vault", "init", true, "vault initialized")
	return shares, nil
}

// UnsealVault unseals the vault with the provided shares.
func (a *App) UnsealVault(shares []shamir.Share) error {
	if err := a.Vault.Unseal(shares); err != nil {
		a.Audit.Log(audit.EventUnseal, "system", "vault", "unseal", false, err.Error())
		return fmt.Errorf("failed to unseal vault: %w", err)
	}

	a.Audit.Log(audit.EventUnseal, "system", "vault", "unseal", true, "vault unsealed")
	return nil
}

// SealVault seals the vault.
func (a *App) SealVault() {
	a.Vault.Seal()
	a.Audit.Log(audit.EventSeal, "system", "vault", "seal", true, "vault sealed")
}
