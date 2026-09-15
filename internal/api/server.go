package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/bagasdisini/polyvault/pkg/audit"
	"github.com/bagasdisini/polyvault/pkg/auth"
	"github.com/bagasdisini/polyvault/pkg/shamir"
	"github.com/bagasdisini/polyvault/pkg/transit"
	"github.com/bagasdisini/polyvault/pkg/vault"
)

// ServerConfig holds the server dependencies.
type ServerConfig struct {
	Vault   *vault.Vault
	Auth    *auth.Authenticator
	Transit *transit.Transit
	Audit   *audit.Logger
	Logger  *slog.Logger
	Addr    string
}

// Server is the HTTP API server.
type Server struct {
	vault         *vault.Vault
	auth          *auth.Authenticator
	transit       *transit.Transit
	audit         *audit.Logger
	logger        *slog.Logger
	mux           *http.ServeMux
	addr          string
	pendingShares []shamir.Share
}

// New creates a new API server.
func New(cfg ServerConfig) *Server {
	s := &Server{
		vault:   cfg.Vault,
		auth:    cfg.Auth,
		transit: cfg.Transit,
		audit:   cfg.Audit,
		logger:  cfg.Logger,
		mux:     http.NewServeMux(),
		addr:    cfg.Addr,
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/sys/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/sys/seal-status", s.handleSealStatus)
	s.mux.HandleFunc("GET /v1/secret", s.handleListSecrets)
	s.mux.HandleFunc("GET /v1/secret/{key}", s.handleGetSecret)

	s.mux.HandleFunc("POST /v1/sys/init", s.handleInit)
	s.mux.HandleFunc("POST /v1/transit/keys/{key}", s.handleTransitCreateKey)
	s.mux.HandleFunc("POST /v1/transit/encrypt/{key}", s.handleTransitEncrypt)
	s.mux.HandleFunc("POST /v1/transit/decrypt/{key}", s.handleTransitDecrypt)

	s.mux.HandleFunc("PUT /v1/sys/seal", s.handleSeal)
	s.mux.HandleFunc("PUT /v1/sys/unseal", s.handleUnseal)
	s.mux.HandleFunc("PUT /v1/secret/{key}", s.handlePutSecret)

	s.mux.HandleFunc("DELETE /v1/secret/{key}", s.handleDeleteSecret)
}

// Handler returns the HTTP handler with middleware applied.
func (s *Server) Handler() http.Handler {
	return s.loggingMiddleware(s.mux)
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      s.loggingMiddleware(s.mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		s.logger.Info("starting API server", "addr", s.addr)
		errChan <- srv.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		return err
	}
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
			"request_id", requestID,
		)
	})
}

func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// --- Handlers ---
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSealStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sealed":      s.vault.State() == vault.StateSealed,
		"state":       s.vault.State().String(),
		"initialized": s.vault.IsInitialized(),
	})
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	if s.vault.IsInitialized() {
		writeError(w, http.StatusConflict, "vault already initialized")
		return
	}

	shares, err := s.vault.Init()
	if err != nil {
		s.logger.Error("init failed", "error", err)
		writeError(w, http.StatusInternalServerError, "init failed")
		return
	}

	// Return shares as hex strings
	shareStrings := make([]string, len(shares))
	for i, share := range shares {
		shareStrings[i] = hex.EncodeToString(share.Values)
	}

	s.audit.Log(audit.EventUnseal, "api", "vault", "init", true, "vault initialized via API")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"shares": shareStrings,
	})
}

type unsealRequest struct {
	Share string `json:"share"`
}

func (s *Server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	if s.vault.State() == vault.StateUnsealed {
		writeError(w, http.StatusConflict, "vault is already unsealed")
		return
	}

	var req unsealRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	shareBytes, err := hex.DecodeString(req.Share)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid share hex")
		return
	}

	share := shamir.Share{
		ID:     1,
		Values: shareBytes,
	}

	s.pendingShares = append(s.pendingShares, share)

	if len(s.pendingShares) < s.vault.Threshold() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sealed":  true,
			"message": fmt.Sprintf("more shares needed (%d/%d)", len(s.pendingShares), s.vault.Threshold()),
		})
		return
	}

	// Accumulated enough shares - try to unseal
	err = s.vault.Unseal(s.pendingShares)
	if err != nil {
		if errors.Is(err, vault.ErrNotEnoughShares) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"sealed":  true,
				"message": "more shares needed",
			})
			return
		}
		s.audit.Log(audit.EventUnseal, "api", "vault", "unseal", false, err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Clear pending shares on success
	s.pendingShares = nil

	s.audit.Log(audit.EventUnseal, "api", "vault", "unseal", true, "vault unsealed via API")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sealed": false,
		"state":  "unsealed",
	})
}

func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request) {
	s.vault.Seal()
	s.audit.Log(audit.EventSeal, "api", "vault", "seal", true, "vault sealed via API")
	writeJSON(w, http.StatusOK, map[string]string{"status": "sealed"})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key")
		return
	}

	value, err := s.vault.Get(key)
	if err != nil {
		if errors.Is(err, vault.ErrVaultSealed) {
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
			return
		}
		if errors.Is(err, vault.ErrSecretNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		s.logger.Error("failed to get secret", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.audit.Log(audit.EventSecretRead, "api", key, "get", true, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key":   key,
		"value": string(value),
	})
}

type putSecretRequest struct {
	Value string `json:"value"`
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key")
		return
	}

	var req putSecretRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	if err := s.vault.Put(key, []byte(req.Value)); err != nil {
		if errors.Is(err, vault.ErrVaultSealed) {
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
			return
		}
		s.logger.Error("failed to put secret", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.audit.Log(audit.EventSecretWrite, "api", key, "put", true, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "key": key})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key")
		return
	}

	if err := s.vault.Delete(key); err != nil {
		if errors.Is(err, vault.ErrVaultSealed) {
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
			return
		}
		if errors.Is(err, vault.ErrSecretNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		s.logger.Error("failed to delete secret", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.audit.Log(audit.EventSecretDelete, "api", key, "delete", true, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	keys, err := s.vault.List()
	if err != nil {
		if errors.Is(err, vault.ErrVaultSealed) {
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
			return
		}
		s.logger.Error("failed to list secrets", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.audit.Log(audit.EventSecretList, "api", "*", "list", true, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keys})
}

// --- Transit handlers ---
type transitEncryptRequest struct {
	Plaintext string `json:"plaintext"`
}

func (s *Server) handleTransitEncrypt(w http.ResponseWriter, r *http.Request) {
	keyName := r.PathValue("key")

	var req transitEncryptRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	encrypted, err := s.transit.Encrypt(keyName, []byte(req.Plaintext))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.audit.Log(audit.EventTransitEnc, "api", keyName, "encrypt", true, "")
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": encrypted})
}

type transitDecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

func (s *Server) handleTransitDecrypt(w http.ResponseWriter, r *http.Request) {
	keyName := r.PathValue("key")

	var req transitDecryptRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	decrypted, err := s.transit.Decrypt(keyName, req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.audit.Log(audit.EventTransitDec, "api", keyName, "decrypt", true, "")
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": string(decrypted)})
}

type transitCreateKeyRequest struct {
	Type string `json:"type"`
}

func (s *Server) handleTransitCreateKey(w http.ResponseWriter, r *http.Request) {
	keyName := r.PathValue("key")

	var req transitCreateKeyRequest
	if err := readJSON(r, &req); err != nil {
		req.Type = "aes256-gcm96"
	}

	keyType := transit.KeyType(req.Type)
	if err := s.transit.CreateKey(keyName, keyType); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "created", "key": keyName})
}

// --- Helpers ---
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func readJSON(r *http.Request, v any) error {
	body := io.LimitReader(r.Body, 1<<20)
	return json.NewDecoder(body).Decode(v)
}
