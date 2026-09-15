package cmd

import (
	"fmt"
	"os"

	"github.com/bagasdisini/polyvault/internal/app"
	"github.com/bagasdisini/polyvault/internal/config"
)

func runInit() error {
	configPath := "config.json"

	cfg, err := config.Load(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to load config: %w", err)
		}
		cfg = config.DefaultConfig()
		if err := cfg.Save(configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	application, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	shares, err := application.InitVault()
	if err != nil {
		return fmt.Errorf("failed to initialize vault: %w", err)
	}

	fmt.Println("\nVault initialized successfully!")
	fmt.Println("\nUnseal Shares (distribute these to trusted operators):")

	for i, share := range shares {
		fmt.Printf("Share %d: %x\n", i+1, share.Values)
	}

	fmt.Println("\nIMPORTANT: Store these shares securely!")
	fmt.Printf("You will need %d of %d shares to unseal the vault.", cfg.Vault.Threshold, cfg.Vault.Total)

	return nil
}
