package cmd

import (
	"fmt"

	"github.com/bagasdisini/polyvault/pkg/vault"
)

func runInit() error {
	fmt.Println("Initializing new vault...")

	v, err := vault.New(vault.Config{Threshold: 3, Total: 5})
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	shares, err := v.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize vault: %w", err)
	}

	fmt.Println("\nVault initialized successfully!")
	fmt.Println("\nUnseal Shares (distribute these to trusted operators):")

	for i, share := range shares {
		fmt.Printf("Share %d: %x\n", i+1, share.Values)
	}

	fmt.Println("\nIMPORTANT: Store these shares securely!")
	fmt.Println("You will need 3 of 5 shares to unseal the vault.")

	return nil
}
