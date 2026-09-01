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
