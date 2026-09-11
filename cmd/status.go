package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func runStatus() error {
	url := fmt.Sprintf("%s/v1/sys/seal-status", serverAddr)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Println("Vault Status")
	fmt.Println("============")
	fmt.Printf("State:  %s\n", result["state"])
	fmt.Printf("Sealed: %v\n", result["sealed"])
	return nil
}
