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

var (
	serverAddr = "http://localhost:8200"
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

func runPut() error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: polyvault put <key> <value>")
	}

	key := os.Args[2]
	value := os.Args[3]

	body, err := json.Marshal(map[string]string{"value": value})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/secret/%s", serverAddr, key)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Printf("Secret '%s' stored successfully\n", key)
	return nil
}

func runGet() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: polyvault get <key>")
	}

	key := os.Args[2]

	url := fmt.Sprintf("%s/v1/secret/%s", serverAddr, key)
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("secret '%s' not found", key)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("Key:    %s\n", result["key"])
	fmt.Printf("Value:  %s\n", result["value"])
	return nil
}

func runDelete() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: polyvault delete <key>")
	}

	key := os.Args[2]

	url := fmt.Sprintf("%s/v1/secret/%s", serverAddr, key)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("secret '%s' not found", key)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Printf("Secret '%s' deleted successfully\n", key)
	return nil
}

func runList() error {
	url := fmt.Sprintf("%s/v1/secret", serverAddr)
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	keys, ok := result["keys"].([]interface{})
	if !ok {
		return fmt.Errorf("unexpected response format")
	}

	fmt.Println("Secrets:")
	fmt.Println("========")
	for _, k := range keys {
		fmt.Printf("  - %s\n", k)
	}
	return nil
}
