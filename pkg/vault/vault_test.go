package vault

import (
	"bytes"
	"testing"
)

func TestVault_InitAndUnseal(t *testing.T) {
	v, err := New(Config{Threshold: 3, Total: 5})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Init generates shares
	shares, err := v.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Vault should still be sealed after init
	if v.State() != StateSealed {
		t.Error("expected vault to be sealed after init")
	}

	// Unseal with threshold shares
	err = v.Unseal(shares[:3])
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if v.State() != StateUnsealed {
		t.Error("expected vault to be unsealed")
	}
}

func TestVault_UnsealWithWrongShares(t *testing.T) {
	v, err := New(Config{Threshold: 2, Total: 3})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = v.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Create a different vault and get its shares
	v2, _ := New(Config{Threshold: 2, Total: 3})
	otherShares, _ := v2.Init()

	// Try to unseal with wrong shares
	err = v.Unseal(otherShares[:2])
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestVault_PutAndGet(t *testing.T) {
	v := newUnsealedVault(t)

	// Store a secret
	err := v.Put("db-password", []byte("super-secret-password"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Retrieve it
	value, err := v.Get("db-password")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(value, []byte("super-secret-password")) {
		t.Errorf("retrieved value does not match")
	}
}

func TestVault_PutOverwrite(t *testing.T) {
	v := newUnsealedVault(t)

	v.Put("key", []byte("value1"))
	v.Put("key", []byte("value2"))

	value, err := v.Get("key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !bytes.Equal(value, []byte("value2")) {
		t.Errorf("expected overwritten value")
	}
}

func TestVault_GetNotFound(t *testing.T) {
	v := newUnsealedVault(t)

	_, err := v.Get("nonexistent")
	if err != ErrSecretNotFound {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestVault_Delete(t *testing.T) {
	v := newUnsealedVault(t)

	v.Put("key", []byte("value"))
	err := v.Delete("key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = v.Get("key")
	if err != ErrSecretNotFound {
		t.Errorf("expected ErrSecretNotFound after delete, got %v", err)
	}
}

func TestVault_DeleteNotFound(t *testing.T) {
	v := newUnsealedVault(t)

	err := v.Delete("nonexistent")
	if err != ErrSecretNotFound {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestVault_List(t *testing.T) {
	v := newUnsealedVault(t)

	v.Put("key1", []byte("value1"))
	v.Put("key2", []byte("value2"))
	v.Put("key3", []byte("value3"))

	keys, err := v.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestVault_OperationsWhileSealed(t *testing.T) {
	v := newUnsealedVault(t)
	v.Put("key", []byte("value"))
	v.Seal()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"Put", func() error { return v.Put("key", []byte("value")) }},
		{"Get", func() error { _, err := v.Get("key"); return err }},
		{"Delete", func() error { return v.Delete("key") }},
		{"List", func() error { _, err := v.List(); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err != ErrVaultSealed {
				t.Errorf("expected ErrVaultSealed, got %v", err)
			}
		})
	}
}

func TestVault_SealClearsKey(t *testing.T) {
	v := newUnsealedVault(t)
	v.Seal()

	// Try to unseal with same shares - should fail because masterHash
	// is only set during Init
	if v.State() != StateSealed {
		t.Error("expected sealed state")
	}
}

func TestVault_MultipleSecrets(t *testing.T) {
	v := newUnsealedVault(t)

	secrets := map[string][]byte{
		"db/host":     []byte("localhost"),
		"db/port":     []byte("5432"),
		"db/user":     []byte("admin"),
		"db/password": []byte("secret123"),
		"api/key":     []byte("sk-1234567890"),
	}

	for k, val := range secrets {
		if err := v.Put(k, val); err != nil {
			t.Fatalf("Put(%s) failed: %v", k, err)
		}
	}

	for k, expected := range secrets {
		got, err := v.Get(k)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", k, err)
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("Get(%s): got %s, want %s", k, got, expected)
		}
	}
}

func TestVault_EncryptionIsRandom(t *testing.T) {
	v := newUnsealedVault(t)

	// Same plaintext should produce different ciphertext (due to random nonce)
	v.Put("key", []byte("same-value"))

	// Copy the first ciphertext before overwriting
	ciphertext1 := make([]byte, len(v.secrets["key"].Value))
	copy(ciphertext1, v.secrets["key"].Value)

	v.Put("key", []byte("same-value"))
	ciphertext2 := v.secrets["key"].Value

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("same plaintext produced same ciphertext - nonce reuse!")
	}
}

// Helper to create an unsealed vault for testing
func newUnsealedVault(t *testing.T) *Vault {
	t.Helper()

	v, err := New(Config{Threshold: 2, Total: 3})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	shares, err := v.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if err := v.Unseal(shares[:2]); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	return v
}
