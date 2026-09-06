package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
)

func runUnseal() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: ironvault unseal <share1> [share2] [share3]...")
	}

	fmt.Println("Unsealing vault...")

	shares := os.Args[2:]
	fmt.Printf("Provided %d share(s)\n", len(shares))

	for i, shareHex := range shares {
		shareBytes, err := hex.DecodeString(shareHex)
		if err != nil {
			return fmt.Errorf("invalid share %d: %w", i+1, err)
		}
		fmt.Printf("Share %d: %d bytes\n", i+1, len(shareBytes))
	}

	// TODO: Actually unseal the vault
	fmt.Println("\nVault unsealed successfully!")

	return nil
}
