package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bagasdisini/polyvault/pkg/vault"
)

func setupTestServer(t *testing.T) (*Server, *vault.Vault) {
	t.Helper()

	v, err := vault.New(vault.Config{Threshold: 2, Total: 3})
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

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	server := New(v, ":0", logger)

	return server, v
}

func TestHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/sys/health", nil)
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%s'", resp["status"])
	}
}

func TestSealStatusEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/sys/seal-status", nil)
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["sealed"] != false {
		t.Error("expected sealed=false")
	}
}

func TestPutAndGetSecret(t *testing.T) {
	server, _ := setupTestServer(t)

	// Put a secret
	putBody, _ := json.Marshal(map[string]string{"value": "my-secret"})
	req := httptest.NewRequest("PUT", "/v1/secret/my-key", bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("PUT: expected 200, got %d", w.Code)
	}

	// Get the secret
	req = httptest.NewRequest("GET", "/v1/secret/my-key", nil)
	w = httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET: expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["value"] != "my-secret" {
		t.Errorf("expected 'my-secret', got '%v'", resp["value"])
	}
}

func TestGetSecretNotFound(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/v1/secret/nonexistent", nil)
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDeleteSecret(t *testing.T) {
	server, _ := setupTestServer(t)

	// Put a secret first
	putBody, _ := json.Marshal(map[string]string{"value": "to-delete"})
	req := httptest.NewRequest("PUT", "/v1/secret/delete-me", bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	// Delete it
	req = httptest.NewRequest("DELETE", "/v1/secret/delete-me", nil)
	w = httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("DELETE: expected 200, got %d", w.Code)
	}

	// Verify it's gone
	req = httptest.NewRequest("GET", "/v1/secret/delete-me", nil)
	w = httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE: expected 404, got %d", w.Code)
	}
}

func TestListSecrets(t *testing.T) {
	server, _ := setupTestServer(t)

	// Put some secrets
	for _, key := range []string{"key1", "key2", "key3"} {
		putBody, _ := json.Marshal(map[string]string{"value": "value"})
		req := httptest.NewRequest("PUT", "/v1/secret/"+key, bytes.NewReader(putBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.mux.ServeHTTP(w, req)
	}

	// List them
	req := httptest.NewRequest("GET", "/v1/secret", nil)
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("LIST: expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	keys := resp["keys"].([]any)
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestSealEndpoint(t *testing.T) {
	server, v := setupTestServer(t)

	req := httptest.NewRequest("PUT", "/v1/sys/seal", nil)
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	if v.State() != vault.StateSealed {
		t.Error("expected vault to be sealed")
	}
}

func TestPutSecretWhileSealed(t *testing.T) {
	server, v := setupTestServer(t)
	v.Seal()

	putBody, _ := json.Marshal(map[string]string{"value": "test"})
	req := httptest.NewRequest("PUT", "/v1/secret/key", bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestPutSecretEmptyValue(t *testing.T) {
	server, _ := setupTestServer(t)

	putBody, _ := json.Marshal(map[string]string{"value": ""})
	req := httptest.NewRequest("PUT", "/v1/secret/key", bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
