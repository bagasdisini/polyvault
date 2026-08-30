package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStore_PutAndGet(t *testing.T) {
	store := newTestStore(t)

	err := store.Put("test-key", []byte("test-value"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	value, err := store.Get("test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(value, []byte("test-value")) {
		t.Errorf("expected 'test-value', got '%s'", value)
	}
}

func TestFileStore_GetNotFound(t *testing.T) {
	store := newTestStore(t)

	_, err := store.Get("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileStore_Overwrite(t *testing.T) {
	store := newTestStore(t)

	store.Put("key", []byte("value1"))
	store.Put("key", []byte("value2"))

	value, err := store.Get("key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(value, []byte("value2")) {
		t.Errorf("expected 'value2', got '%s'", value)
	}
}

func TestFileStore_Delete(t *testing.T) {
	store := newTestStore(t)

	store.Put("key", []byte("value"))
	err := store.Delete("key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = store.Get("key")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestFileStore_DeleteNotFound(t *testing.T) {
	store := newTestStore(t)

	// Deleting non-existent key should not error
	err := store.Delete("nonexistent")
	if err != nil {
		t.Errorf("Delete of non-existent key should not error, got %v", err)
	}
}

func TestFileStore_List(t *testing.T) {
	store := newTestStore(t)

	store.Put("key1", []byte("value1"))
	store.Put("key2", []byte("value2"))
	store.Put("key3", []byte("value3"))

	keys, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestFileStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	store.Put("key", []byte("value"))

	// Check that no temp files remain
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Error("temp file left behind after atomic write")
		}
	}
}

func TestFileStore_PathSanitization(t *testing.T) {
	store := newTestStore(t)

	// Attempt path traversal
	err := store.Put("../../../etc/passwd", []byte("evil"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Should be stored safely
	value, err := store.Get("../../../etc/passwd")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(value, []byte("evil")) {
		t.Error("value mismatch")
	}
}

func TestSaveLoadVaultData(t *testing.T) {
	store := newTestStore(t)

	data := &VaultData{
		MasterHash: []byte("test-hash"),
		Threshold:  3,
		Total:      5,
		Secrets: map[string]SecretData{
			"key1": {Key: "key1", Value: []byte("encrypted1"), Version: 1},
			"key2": {Key: "key2", Value: []byte("encrypted2"), Version: 2},
		},
	}

	err := SaveVaultData(store, data)
	if err != nil {
		t.Fatalf("SaveVaultData failed: %v", err)
	}

	loaded, err := LoadVaultData(store)
	if err != nil {
		t.Fatalf("LoadVaultData failed: %v", err)
	}

	if loaded.Threshold != data.Threshold {
		t.Errorf("threshold: got %d, want %d", loaded.Threshold, data.Threshold)
	}

	if loaded.Total != data.Total {
		t.Errorf("total: got %d, want %d", loaded.Total, data.Total)
	}

	if len(loaded.Secrets) != len(data.Secrets) {
		t.Errorf("secrets count: got %d, want %d", len(loaded.Secrets), len(data.Secrets))
	}
}

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}
	return store
}
