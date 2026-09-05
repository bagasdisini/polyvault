package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrTokenNotFound = errors.New("auth: token not found")
	ErrTokenExpired  = errors.New("auth: token expired")
)

// Policy represents an access control policy.
type Policy string

const (
	PolicyRead    Policy = "read"
	PolicyWrite   Policy = "write"
	PolicyDelete  Policy = "delete"
	PolicyList    Policy = "list"
	PolicyAdmin   Policy = "admin"
	PolicyTransit Policy = "transit"
)

// Token represents an authentication token.
type Token struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // SHA-256 of the raw token
	Name      string    `json:"name"`
	Policies  []Policy  `json:"policies"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Authenticator manages tokens and authentication.
type Authenticator struct {
	mu     sync.RWMutex
	tokens map[string]*Token // hash -> token
}

// New creates a new Authenticator.
func New() *Authenticator {
	return &Authenticator{
		tokens: make(map[string]*Token),
	}
}

// CreateToken generates a new authentication token.
// Returns the raw token (only shown once) and the token metadata.
func (a *Authenticator) CreateToken(name string, policies []Policy, ttl time.Duration) (string, *Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Generate random token
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	rawToken := hex.EncodeToString(raw)

	// Hash the token for storage
	hash := hashToken(rawToken)

	token := &Token{
		ID:        generateID(),
		Hash:      hash,
		Name:      name,
		Policies:  policies,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	a.tokens[hash] = token

	return rawToken, token, nil
}

// Validate checks if a token is valid and returns its metadata.
func (a *Authenticator) Validate(rawToken string) (*Token, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	hash := hashToken(rawToken)

	token, exists := a.tokens[hash]
	if !exists {
		return nil, ErrTokenNotFound
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return token, nil
}

// Revoke removes a token.
func (a *Authenticator) Revoke(rawToken string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	hash := hashToken(rawToken)

	if _, exists := a.tokens[hash]; !exists {
		return ErrTokenNotFound
	}

	delete(a.tokens, hash)
	return nil
}

// HasPolicy checks if a token has a specific policy.
func (t *Token) HasPolicy(policy Policy) bool {
	for _, p := range t.Policies {
		if p == PolicyAdmin {
			return true // admin has all permissions
		}
		if p == policy {
			return true
		}
	}
	return false
}

// ListTokens returns all tokens (without sensitive data).
func (a *Authenticator) ListTokens() []*Token {
	a.mu.RLock()
	defer a.mu.RUnlock()

	tokens := make([]*Token, 0, len(a.tokens))
	for _, t := range a.tokens {
		tokens = append(tokens, &Token{
			ID:        t.ID,
			Name:      t.Name,
			Policies:  t.Policies,
			ExpiresAt: t.ExpiresAt,
			CreatedAt: t.CreatedAt,
		})
	}
	return tokens
}

// Cleanup removes expired tokens.
func (a *Authenticator) Cleanup() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	removed := 0

	for hash, token := range a.tokens {
		if now.After(token.ExpiresAt) {
			delete(a.tokens, hash)
			removed++
		}
	}

	return removed
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
