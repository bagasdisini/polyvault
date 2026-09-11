package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func runUnseal() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: polyvault unseal <share1> [share2] [share3]...")
	}

	shares := os.Args[2:]

	fmt.Println("Unsealing vault...")
	client := &http.Client{Timeout: 30 * time.Second}
	baseURL := fmt.Sprintf("%s/v1/sys/unseal", serverAddr)

	for i, shareHex := range shares {
		body, err := json.Marshal(map[string]string{"share": shareHex})
		if err != nil {
			return fmt.Errorf("failed to marshal share %d: %w", i+1, err)
		}

		resp, err := client.Post(baseURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to send share %d request: %w", i+1, err)
		}

		responseBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result map[string]interface{}
		if err := json.Unmarshal(responseBody, &result); err != nil {
			return fmt.Errorf("failed to decode response for share %d: %w", i+1, err)
		}

		fmt.Printf("Share %d submitted\n", i+1)

		isSealed, _ := result["sealed"].(bool)
		if !isSealed {
			fmt.Println("Vault unsealed successfully!")
			return nil
		}
	}

	// Check final state
	fmt.Println("Vault is still sealed. More shares required.")
	return nil
}
