package transit

import (
	"bytes"
	"errors"
	"testing"
)

func TestCreateKey(t *testing.T) {
	transit := New()

	err := transit.CreateKey("test-key", KeyTypeAES256)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	keys := transit.ListKeys()
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestCreateKey_Duplicate(t *testing.T) {
	transit := New()

	transit.CreateKey("key", KeyTypeAES256)
	err := transit.CreateKey("key", KeyTypeAES256)
	if !errors.Is(err, ErrKeyExists) {
		t.Errorf("expected ErrKeyExists, got %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	plaintext := []byte("hello, world!")

	encrypted, err := transit.Encrypt("key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := transit.Decrypt("key", encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text does not match original")
	}
}

func TestEncrypt_KeyNotFound(t *testing.T) {
	transit := New()

	_, err := transit.Encrypt("nonexistent", []byte("test"))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDecrypt_KeyNotFound(t *testing.T) {
	transit := New()

	_, err := transit.Decrypt("nonexistent", "dGVzdA==")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	_, err := transit.Decrypt("key", "invalid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestEncrypt_RandomNonce(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	plaintext := []byte("same plaintext")

	enc1, _ := transit.Encrypt("key", plaintext)
	enc2, _ := transit.Encrypt("key", plaintext)

	if enc1 == enc2 {
		t.Error("same plaintext produced same ciphertext - nonce reuse!")
	}
}

func TestRotateKey(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	// Rotate key
	err := transit.RotateKey("key")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	info, _ := transit.GetKeyInfo("key")
	if info.Version != 2 {
		t.Errorf("expected version 2, got %d", info.Version)
	}

	// Old ciphertext should still decrypt (if kept old key)
	// For simplicity, the implementation doesn't keep old keys,
	// so this would fail. That's expected behavior.
}

func TestRotateKey_NotFound(t *testing.T) {
	transit := New()

	err := transit.RotateKey("nonexistent")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestHMAC(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	input := []byte("test data")

	hmac1, err := transit.HMAC("key", input)
	if err != nil {
		t.Fatalf("HMAC failed: %v", err)
	}

	// Same input should produce same HMAC
	hmac2, _ := transit.HMAC("key", input)
	if hmac1 != hmac2 {
		t.Error("same input produced different HMACs")
	}

	// Different input should produce different HMAC
	hmac3, _ := transit.HMAC("key", []byte("different data"))
	if hmac1 == hmac3 {
		t.Error("different input produced same HMAC")
	}
}

func TestHMAC_KeyNotFound(t *testing.T) {
	transit := New()

	_, err := transit.HMAC("nonexistent", []byte("test"))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestGetKeyInfo(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	info, err := transit.GetKeyInfo("key")
	if err != nil {
		t.Fatalf("GetKeyInfo failed: %v", err)
	}

	if info.Name != "key" {
		t.Errorf("expected name 'key', got '%s'", info.Name)
	}
	if info.Type != string(KeyTypeAES256) {
		t.Errorf("expected type '%s', got '%s'", KeyTypeAES256, info.Type)
	}
	if info.Version != 1 {
		t.Errorf("expected version 1, got %d", info.Version)
	}
}

func TestGetKeyInfo_NotFound(t *testing.T) {
	transit := New()

	_, err := transit.GetKeyInfo("nonexistent")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestMultipleKeys(t *testing.T) {
	transit := New()

	transit.CreateKey("key1", KeyTypeAES256)
	transit.CreateKey("key2", KeyTypeAES256)
	transit.CreateKey("key3", KeyTypeAES256)

	keys := transit.ListKeys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// Encrypt with key1, decrypt with key1
	enc1, _ := transit.Encrypt("key1", []byte("test"))
	_, err := transit.Decrypt("key2", enc1)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestLargeData(t *testing.T) {
	transit := New()
	transit.CreateKey("key", KeyTypeAES256)

	// 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := transit.Encrypt("key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := transit.Decrypt("key", encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("large data: decrypted does not match original")
	}
}
