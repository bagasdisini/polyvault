package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/bagasdisini/polyvault/internal/app"
	"github.com/bagasdisini/polyvault/internal/config"
)

func runServer() error {
	configPath := "config.json"
	addr := ":8200"

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--config", "-c":
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
				i++
			}
		case "--addr", "-a":
			if i+1 < len(os.Args) {
				addr = os.Args[i+1]
				i++
			}
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to load config: %w", err)
		}
		// Config doesn't exist - create default
		cfg = config.DefaultConfig()
		cfg.Server.Addr = addr
		if err := cfg.Save(configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	} else {
		cfg.Server.Addr = addr
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	application, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	application.Logger = logger
	return application.StartServer()
}
