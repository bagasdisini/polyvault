package tests

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bagasdisini/polyvault/internal/api"
	"github.com/bagasdisini/polyvault/pkg/audit"
	"github.com/bagasdisini/polyvault/pkg/auth"
	"github.com/bagasdisini/polyvault/pkg/storage"
	"github.com/bagasdisini/polyvault/pkg/transit"
	"github.com/bagasdisini/polyvault/pkg/vault"
)

func newTestHTTPServer(t *testing.T) *api.Server {
	t.Helper()

	tmpDir := t.TempDir()

	store, err := storage.NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	v, err := vault.New(vault.Config{Threshold: 2, Total: 3, Storage: store})
	if err != nil {
		t.Fatalf("vault.New failed: %v", err)
	}

	shares, err := v.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if err := v.Unseal(shares[:2]); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	authenticator := auth.New()
	transitEngine := transit.New()
	a := audit.New([]byte("test-key"), &bytes.Buffer{})

	srv := api.New(api.ServerConfig{
		Vault:   v,
		Auth:    authenticator,
		Transit: transitEngine,
		Audit:   a,
		Logger:  logger,
		Addr:    ":0",
	})

	return srv
}

// TestFullWorkflow end-to-end tests secret lifecycle via HTTP
func TestFullWorkflow(t *testing.T) {
	srv := newTestHTTPServer(t)

	client := &http.Client{Timeout: 5 * time.Second}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Health check
	resp, err := client.Get(ts.URL + "/v1/sys/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Store a secret
	body, _ := json.Marshal(map[string]string{"value": "secret-value"})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/secret/mykey", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT: expected 200, got %d", resp.StatusCode)
	}

	// Retrieve the secret
	resp, err = client.Get(ts.URL + "/v1/secret/mykey")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["value"] != "secret-value" {
		t.Errorf("expected 'secret-value', got '%v'", result["value"])
	}

	// List secrets
	resp, err = client.Get(ts.URL + "/v1/secret")
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&result)
	keys := result["keys"].([]interface{})
	if len(keys) < 1 {
		t.Error("expected at least 1 secret in list")
	}

	// Delete the secret
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/v1/secret/mykey", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DELETE failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE: expected 200, got %d", resp.StatusCode)
	}

	// Verify deleted
	resp, err = client.Get(ts.URL + "/v1/secret/mykey")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 after delete, got %d", resp.StatusCode)
		}
	}
}

// TestSealedVaultRejectsOperations verifies operations fail when vault is sealed
func TestSealedVaultRejectsOperations(t *testing.T) {
	srv := newTestHTTPServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// Seal the vault
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/sys/seal", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("seal request failed: %v", err)
	}
	resp.Body.Close()

	// Try to put a secret while sealed
	body, _ := json.Marshal(map[string]string{"value": "test"})
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/v1/secret/key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT while sealed request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when sealed, got %d", resp.StatusCode)
	}
}

// TestMultipleSecrets stores and retrieves multiple secrets simultaneously
func TestMultipleSecrets(t *testing.T) {
	srv := newTestHTTPServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	secrets := map[string]string{
		"db.host": "localhost",
		"db.port": "5432",
		"api.key": "sk-1234567890",
	}

	for k, v := range secrets {
		body, _ := json.Marshal(map[string]string{"value": v})
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/secret/"+k, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT(%s) failed: %v", k, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("PUT(%s): expected 200, got %d", k, resp.StatusCode)
		}
	}

	// List and verify all present
	resp, err := client.Get(ts.URL + "/v1/secret")
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	keys := result["keys"].([]interface{})
	if len(keys) != len(secrets) {
		t.Errorf("expected %d keys, got %d", len(secrets), len(keys))
	}
}

// TestPersistenceAcrossRestart simulates restart by creating new app from same storage
func TestPersistenceAcrossRestart(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := storage.NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	v1, err := vault.New(vault.Config{Threshold: 2, Total: 3, Storage: store})
	if err != nil {
		t.Fatalf("vault.New failed: %v", err)
	}
	shares, err := v1.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if err := v1.Unseal(shares[:2]); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	// Put a secret before "restart"
	if err := v1.Put("persist-key", []byte("persist-value")); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Simulate restart - create new vault from same storage
	v2, err := vault.New(vault.Config{Threshold: 2, Total: 3, Storage: store})
	if err != nil {
		t.Fatalf("re-init vault failed: %v", err)
	}

	if !v2.IsInitialized() {
		t.Fatal("vault should be initialized after restart")
	}

	// Note: Full persistence test would need unseal shares to be preserved across restart
	// For now we verify the metadata persisted (initialized state)
}

// TestTransitEncryption tests the full transit encrypt/decrypt cycle
func TestTransitEncryption(t *testing.T) {
	srv := newTestHTTPServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// Create a transit key
	body, _ := json.Marshal(map[string]string{"type": "aes256-gcm96"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/transit/keys/test-key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create transit key failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("create key: expected 200, got %d", resp.StatusCode)
	}

	// Encrypt
	encBody, _ := json.Marshal(map[string]string{"plaintext": "hello world"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/transit/encrypt/test-key", bytes.NewReader(encBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	defer resp.Body.Close()

	var encResult map[string]string
	json.NewDecoder(resp.Body).Decode(&encResult)
	ciphertext := encResult["ciphertext"]
	if ciphertext == "" {
		t.Fatal("expected non-empty ciphertext")
	}

	// Decrypt
	decBody, _ := json.Marshal(map[string]string{"ciphertext": ciphertext})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/transit/decrypt/test-key", bytes.NewReader(decBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	defer resp.Body.Close()

	var decResult map[string]string
	json.NewDecoder(resp.Body).Decode(&decResult)
	if decResult["plaintext"] != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", decResult["plaintext"])
	}
}
