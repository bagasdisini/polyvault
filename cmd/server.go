package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/bagasdisini/polyvault/internal/api"
	"github.com/bagasdisini/polyvault/pkg/vault"
)

func runServer() error {
	addr := ":8200"
	dataDir := "./vault-data"

	// Parse flags
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--addr", "-a":
			if i+1 < len(os.Args) {
				addr = os.Args[i+1]
				i++
			}
		case "--data-dir", "-d":
			if i+1 < len(os.Args) {
				dataDir = os.Args[i+1]
				i++
			}
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create vault
	v, err := vault.New(vault.Config{Threshold: 3, Total: 5})
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	// TODO: Load existing vault data from dataDir
	_ = dataDir

	// Create and start API server
	server := api.New(v, addr, logger)
	return server.Start()
}
