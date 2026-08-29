package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bagasdisini/polyvault/pkg/shamir"
)

var (
	ErrVaultSealed     = errors.New("vault: vault is sealed")
	ErrVaultUnsealed   = errors.New("vault: vault is already unsealed")
	ErrSecretNotFound  = errors.New("vault: secret not found")
	ErrInvalidKey      = errors.New("vault: invalid master key")
	ErrNotEnoughShares = errors.New("vault: not enough shares provided")
)

// VaultState represents whether the vault is sealed or unsealed.
type VaultState int

const (
	StateSealed VaultState = iota
	StateUnsealed
)

func (s VaultState) String() string {
	switch s {
	case StateSealed:
		return "sealed"
	case StateUnsealed:
		return "unsealed"
	default:
		return "unknown"
	}
}

// Secret represents a stored secret with metadata.
type Secret struct {
	Key       string    `json:"key"`
	Value     []byte    `json:"value"` // encrypted
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int       `json:"version"`
}

// Vault is the core secrets management engine.
type Vault struct {
	mu sync.RWMutex

	state      VaultState
	masterKey  []byte // 32 bytes, only present when unsealed
	masterHash []byte // SHA-256 of master key, for verification

	secrets map[string]*Secret

	// Shamir configuration
	threshold int
	total     int
	shares    []shamir.Share // stored shares for re-sealing
}

// Config holds vault configuration.
type Config struct {
	Threshold int // minimum shares needed to unseal
	Total     int // total shares to generate
}

// New creates a new vault. The vault starts sealed.
func New(cfg Config) (*Vault, error) {
	if cfg.Threshold < 2 {
		return nil, errors.New("vault: threshold must be >= 2")
	}
	if cfg.Total < cfg.Threshold {
		return nil, errors.New("vault: total must be >= threshold")
	}

	return &Vault{
		state:     StateSealed,
		secrets:   make(map[string]*Secret),
		threshold: cfg.Threshold,
		total:     cfg.Total,
	}, nil
}

// Init generates a new master key and splits it using Shamir's Secret Sharing.
// Returns the shares that must be distributed to key holders.
// This should only be called once when initializing a new vault.
func (v *Vault) Init() ([]shamir.Share, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state == StateUnsealed {
		return nil, ErrVaultUnsealed
	}

	// Generate 32-byte master key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("vault: failed to generate master key: %w", err)
	}

	// Split the master key
	shares, err := shamir.Split(masterKey, v.threshold, v.total)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to split master key: %w", err)
	}

	// Store the hash for verification
	hash := sha256.Sum256(masterKey)
	v.masterHash = hash[:]

	// Store shares for potential re-sealing
	v.shares = shares

	return shares, nil
}

// Unseal provides shares to reconstruct the master key.
// Must provide at least Threshold shares.
func (v *Vault) Unseal(shares []shamir.Share) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state == StateUnsealed {
		return ErrVaultUnsealed
	}

	if len(shares) < v.threshold {
		return ErrNotEnoughShares
	}

	// Reconstruct the master key
	masterKey, err := shamir.Combine(shares[:v.threshold])
	if err != nil {
		return fmt.Errorf("vault: failed to reconstruct master key: %w", err)
	}

	// Verify against stored hash
	hash := sha256.Sum256(masterKey)
	if !bytesEqual(hash[:], v.masterHash) {
		return ErrInvalidKey
	}

	v.masterKey = masterKey
	v.state = StateUnsealed

	return nil
}

// Seal locks the vault, clearing the master key from memory.
func (v *Vault) Seal() {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Zero out the master key
	for i := range v.masterKey {
		v.masterKey[i] = 0
	}
	v.masterKey = nil
	v.state = StateSealed
}

// State returns the current vault state.
func (v *Vault) State() VaultState {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.state
}

// Put stores a secret. The vault must be unsealed.
func (v *Vault) Put(key string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state == StateSealed {
		return ErrVaultSealed
	}

	// Encrypt the value
	encrypted, err := v.encrypt(value)
	if err != nil {
		return fmt.Errorf("vault: failed to encrypt secret: %w", err)
	}

	now := time.Now().UTC()
	existing, exists := v.secrets[key]
	if exists {
		existing.Value = encrypted
		existing.UpdatedAt = now
		existing.Version++
	} else {
		v.secrets[key] = &Secret{
			Key:       key,
			Value:     encrypted,
			CreatedAt: now,
			UpdatedAt: now,
			Version:   1,
		}
	}

	return nil
}

// Get retrieves a secret. The vault must be unsealed.
func (v *Vault) Get(key string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == StateSealed {
		return nil, ErrVaultSealed
	}

	secret, exists := v.secrets[key]
	if !exists {
		return nil, ErrSecretNotFound
	}

	// Decrypt the value
	decrypted, err := v.decrypt(secret.Value)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to decrypt secret: %w", err)
	}

	return decrypted, nil
}

// Delete removes a secret. The vault must be unsealed.
func (v *Vault) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.state == StateSealed {
		return ErrVaultSealed
	}

	if _, exists := v.secrets[key]; !exists {
		return ErrSecretNotFound
	}

	delete(v.secrets, key)
	return nil
}

// List returns all secret keys (not values). The vault must be unsealed.
func (v *Vault) List() ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.state == StateSealed {
		return nil, ErrVaultSealed
	}

	keys := make([]string, 0, len(v.secrets))
	for k := range v.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

// encrypt encrypts data using AES-GCM with the master key.
func (v *Vault) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// nonce + ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts data using AES-GCM with the master key.
func (v *Vault) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("vault: ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Export exports the vault state (encrypted secrets) for backup.
func (v *Vault) Export() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	data := struct {
		Secrets   map[string]*Secret `json:"secrets"`
		Threshold int                `json:"threshold"`
		Total     int                `json:"total"`
		Hash      []byte             `json:"master_hash"`
	}{
		Secrets:   v.secrets,
		Threshold: v.threshold,
		Total:     v.total,
		Hash:      v.masterHash,
	}

	return json.MarshalIndent(data, "", "  ")
}

// bytesEqual performs a constant-time comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
