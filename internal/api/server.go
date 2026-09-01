package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/bagasdisini/polyvault/pkg/vault"
)

// Server is the HTTP API server.
type Server struct {
	vault  *vault.Vault
	logger *slog.Logger
	mux    *http.ServeMux
	addr   string
}

// New creates a new API server.
func New(v *vault.Vault, addr string, logger *slog.Logger) *Server {
	s := &Server{
		vault:  v,
		logger: logger,
		mux:    http.NewServeMux(),
		addr:   addr,
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/sys/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/sys/seal-status", s.handleSealStatus)
	s.mux.HandleFunc("GET /v1/secret", s.handleListSecrets)
	s.mux.HandleFunc("GET /v1/secret/{key}", s.handleGetSecret)

	s.mux.HandleFunc("PUT /v1/sys/seal", s.handleSeal)
	s.mux.HandleFunc("PUT /v1/sys/unseal", s.handleUnseal)
	s.mux.HandleFunc("PUT /v1/secret/{key}", s.handlePutSecret)

	s.mux.HandleFunc("DELETE /v1/secret/{key}", s.handleDeleteSecret)
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

	s.logger.Info("starting API server", "addr", s.addr)
	return srv.ListenAndServe()
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

// --- Handlers ---
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleSealStatus(w http.ResponseWriter, r *http.Request) {
	state := s.vault.State()
	writeJSON(w, http.StatusOK, map[string]any{
		"sealed": state == vault.StateSealed,
		"state":  state.String(),
	})
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

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": keys,
	})
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

	writeJSON(w, http.StatusOK, map[string]any{
		"key":   key,
		"value": string(value),
	})
}

func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request) {
	s.vault.Seal()
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "sealed",
	})
}

type unsealRequest struct {
	Share []byte `json:"share"`
}

func (s *Server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var req unsealRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// TODO: Implement this
	writeError(w, http.StatusNotImplemented, "single-share unseal not yet implemented")
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

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"key":    key,
	})
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

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
	})
}

// --- Helpers ---
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

func readJSON(r *http.Request, v any) error {
	body := io.LimitReader(r.Body, 1<<20) // 1MB limit
	return json.NewDecoder(body).Decode(v)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
