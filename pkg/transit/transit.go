package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrKeyNotFound       = errors.New("transit: key not found")
	ErrKeyExists         = errors.New("transit: key already exists")
	ErrInvalidCiphertext = errors.New("transit: invalid ciphertext")
	ErrUnsupportedKey    = errors.New("transit: unsupported key type")
	ErrGenerateKey       = errors.New("transit: failed to generate key")
	ErrGenerateNonce     = errors.New("transit: failed to generate nonce")
	ErrCreateCipher      = errors.New("transit: failed to create cipher")
	ErrCreateGCM         = errors.New("transit: failed to create GCM")
	ErrInvalidBase64     = errors.New("transit: invalid base64")
	ErrDecryptFailed     = errors.New("transit: decryption failed")
)

const (
	KeyTypeAES256 KeyType = "aes256-gcm96"
)

// KeyType represents the type of encryption key.
type KeyType string

// Key represents an encryption key managed by the transit engine.
type Key struct {
	Name      string  `json:"name"`
	Type      KeyType `json:"type"`
	Key       []byte  `json:"key"` // raw key material
	Version   int     `json:"version"`
	CreatedAt int64   `json:"created_at"`
}

// Transit is the encryption-as-a-service engine.
type Transit struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

// New creates a new Transit engine.
func New() *Transit {
	return &Transit{
		keys: make(map[string]*Key),
	}
}

// CreateKey generates a new encryption key.
func (t *Transit) CreateKey(name string, keyType KeyType) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.keys[name]; exists {
		return ErrKeyExists
	}

	var keySize int
	switch keyType {
	case KeyTypeAES256:
		keySize = 32
	default:
		return fmt.Errorf(ErrUnsupportedKey.Error()+": %s", keyType)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf(ErrGenerateKey.Error()+": %w", err)
	}

	t.keys[name] = &Key{
		Name:    name,
		Type:    keyType,
		Key:     key,
		Version: 1,
	}

	return nil
}

// RotateKey generates a new version of an existing key.
func (t *Transit) RotateKey(name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	existing, exists := t.keys[name]
	if !exists {
		return ErrKeyNotFound
	}

	var keySize int
	switch existing.Type {
	case KeyTypeAES256:
		keySize = 32
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf(ErrGenerateKey.Error()+": %w", err)
	}

	existing.Key = key
	existing.Version++

	return nil
}

// Encrypt encrypts plaintext using the named key.
// Returns base64-encoded ciphertext.
func (t *Transit) Encrypt(keyName string, plaintext []byte) (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, exists := t.keys[keyName]
	if !exists {
		return "", ErrKeyNotFound
	}

	switch key.Type {
	case KeyTypeAES256:
		return t.encryptAES(key, plaintext)
	default:
		return "", fmt.Errorf(ErrUnsupportedKey.Error()+": %s", key.Type)
	}
}

// Decrypt decrypts base64-encoded ciphertext using the named key.
func (t *Transit) Decrypt(keyName string, ciphertext string) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, exists := t.keys[keyName]
	if !exists {
		return nil, ErrKeyNotFound
	}

	switch key.Type {
	case KeyTypeAES256:
		return t.decryptAES(key, ciphertext)
	default:
		return nil, fmt.Errorf(ErrUnsupportedKey.Error()+": %s", key.Type)
	}
}

// HMAC computes an HMAC-SHA256 of the input using the named key.
func (t *Transit) HMAC(keyName string, input []byte) (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, exists := t.keys[keyName]
	if !exists {
		return "", ErrKeyNotFound
	}

	mac := sha256.New()
	mac.Write(key.Key)
	mac.Write(input)
	result := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(result), nil
}

// ListKeys returns the names of all managed keys.
func (t *Transit) ListKeys() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	keys := make([]string, 0, len(t.keys))
	for name := range t.keys {
		keys = append(keys, name)
	}
	return keys
}

// GetKeyInfo returns metadata about a key (not the key material).
func (t *Transit) GetKeyInfo(name string) (*KeyInfo, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, exists := t.keys[name]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return &KeyInfo{
		Name:    key.Name,
		Type:    string(key.Type),
		Version: key.Version,
	}, nil
}

// KeyInfo contains metadata about a key.
type KeyInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version int    `json:"version"`
}

func (t *Transit) encryptAES(key *Key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return "", fmt.Errorf(ErrCreateCipher.Error()+": %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf(ErrCreateGCM.Error()+": %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf(ErrGenerateNonce.Error()+": %w", err)
	}

	// Format: version (1 byte) + nonce + ciphertext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := make([]byte, 1+len(nonce)+len(ciphertext))
	result[0] = byte(key.Version)
	copy(result[1:], nonce)
	copy(result[1+len(nonce):], ciphertext)

	return base64.StdEncoding.EncodeToString(result), nil
}

func (t *Transit) decryptAES(key *Key, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf(ErrInvalidBase64.Error()+": %w", err)
	}

	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf(ErrCreateCipher.Error()+": %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf(ErrCreateGCM.Error()+": %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < 1+nonceSize {
		return nil, ErrInvalidCiphertext
	}

	// Skip version byte
	nonce := data[1 : 1+nonceSize]
	ciphertext := data[1+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrDecryptFailed.Error()+": %w", err)
	}

	return plaintext, nil
}
