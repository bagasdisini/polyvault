package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrNotFound         = errors.New("storage: key not found")
	ErrFailedRead       = errors.New("storage: failed to read file")
	ErrFailedWrite      = errors.New("storage: failed to write to file")
	ErrFailedCreate     = errors.New("storage: failed to create directory")
	ErrFailedRename     = errors.New("storage: failed to rename file")
	ErrFailedMarshal    = errors.New("storage: failed to marshal data")
	ErrFailedUnmarshall = errors.New("storage: failed to unmarshal data")
)

// Store defines the interface for persistent storage.
type Store interface {
	Get(key string) ([]byte, error)
	List() ([]string, error)
	Put(key string, value []byte) error
	Delete(key string) error
	Close() error
}

// FileStore implements Store using the filesystem.
// Each key is stored as a separate file. Writes are atomic (write-to-temp + rename).
type FileStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileStore creates a new file-based store in the given directory.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf(ErrFailedCreate.Error()+": ", err)
	}

	return &FileStore{
		dir: dir,
	}, nil
}

func (fs *FileStore) path(key string) string {
	safe := filepath.Base(key)
	return filepath.Join(fs.dir, safe+".json")
}

// Put stores data atomically using write-to-temp + rename.
func (fs *FileStore) Put(key string, value []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := fs.path(key)
	tmpPath := path + ".tmp"

	// Write to temp file
	if err := os.WriteFile(tmpPath, value, 0600); err != nil {
		return fmt.Errorf(ErrFailedWrite.Error()+": ", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // cleanup
		return fmt.Errorf(ErrFailedRename.Error()+": ", err)
	}

	return nil
}

// Get retrieves data by key.
func (fs *FileStore) Get(key string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := fs.path(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf(ErrFailedRead.Error()+": ", err)
	}

	return data, nil
}

// Delete removes a key.
func (fs *FileStore) Delete(key string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := fs.path(key)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf(ErrFailedRead.Error()+": ", err)
	}

	return nil
}

// List returns all stored keys.
func (fs *FileStore) List() ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedRead.Error()+": ", err)
	}

	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		// Remove .json extension
		name := entry.Name()
		keys = append(keys, name[:len(name)-5])
	}

	return keys, nil
}

// Close is a no-op for FileStore.
func (fs *FileStore) Close() error {
	return nil
}

// VaultData represents the serialized vault state.
type VaultData struct {
	MasterHash []byte                `json:"master_hash"`
	Threshold  int                   `json:"threshold"`
	Total      int                   `json:"total"`
	Secrets    map[string]SecretData `json:"secrets"`
}

// SecretData represents a serialized secret.
type SecretData struct {
	Key       string `json:"key"`
	Value     []byte `json:"value"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	Version   int    `json:"version"`
}

// SaveVaultData serializes and saves vault data to the store.
func SaveVaultData(store Store, data *VaultData) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf(ErrFailedMarshal.Error()+": ", err)
	}

	return store.Put("__vault__", encoded)
}

// LoadVaultData loads vault data from the store.
func LoadVaultData(store Store) (*VaultData, error) {
	data, err := store.Get("__vault__")
	if err != nil {
		return nil, err
	}

	var vaultData VaultData
	if err := json.Unmarshal(data, &vaultData); err != nil {
		return nil, fmt.Errorf(ErrFailedUnmarshall.Error()+": ", err)
	}

	return &vaultData, nil
}
