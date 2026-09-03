package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	key := []byte("test-audit-key")
	logger := New(key, &buf)

	err := logger.Log(EventSecretRead, "user1", "db-password", "read", true, "")
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	// Should have written something
	if buf.Len() == 0 {
		t.Error("no output written")
	}

	// Should be valid JSON
	var entry Entry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if entry.EventType != EventSecretRead {
		t.Errorf("expected event type '%s', got '%s'", EventSecretRead, entry.EventType)
	}
	if entry.Actor != "user1" {
		t.Errorf("expected actor 'user1', got '%s'", entry.Actor)
	}
}

func TestLogger_ChainIntegrity(t *testing.T) {
	var buf bytes.Buffer
	key := []byte("test-key")
	logger := New(key, &buf)

	// Log several events
	logger.Log(EventSecretWrite, "user1", "key1", "write", true, "")
	logger.Log(EventSecretRead, "user2", "key2", "read", true, "")
	logger.Log(EventSecretDelete, "user1", "key3", "delete", false, "permission denied")

	// Parse all entries
	entries := parseEntries(t, buf.Bytes())

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify chain
	if err := Verify(key, entries); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

func TestVerify_TamperedEntry(t *testing.T) {
	var buf bytes.Buffer
	key := []byte("test-key")
	logger := New(key, &buf)

	logger.Log(EventSecretRead, "user1", "key1", "read", true, "")
	logger.Log(EventSecretWrite, "user1", "key2", "write", true, "")

	entries := parseEntries(t, buf.Bytes())

	// Tamper with an entry
	entries[1].Actor = "attacker"

	err := Verify(key, entries)
	if err == nil {
		t.Error("expected verification to fail after tampering")
	}
}

func TestVerify_TamperedChain(t *testing.T) {
	var buf bytes.Buffer
	key := []byte("test-key")
	logger := New(key, &buf)

	logger.Log(EventSecretRead, "user1", "key1", "read", true, "")
	logger.Log(EventSecretWrite, "user1", "key2", "write", true, "")
	logger.Log(EventSecretDelete, "user1", "key3", "delete", true, "")

	entries := parseEntries(t, buf.Bytes())

	// Remove middle entry (simulating deletion)
	tampered := []Entry{entries[0], entries[2]}

	err := Verify(key, tampered)
	if err == nil {
		t.Error("expected verification to fail after entry deletion")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	var buf bytes.Buffer
	key := []byte("correct-key")
	logger := New(key, &buf)

	logger.Log(EventSecretRead, "user1", "key1", "read", true, "")

	entries := parseEntries(t, buf.Bytes())

	// Verify with wrong key
	wrongKey := []byte("wrong-key")
	err := Verify(wrongKey, entries)
	if err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestVerify_EmptyLog(t *testing.T) {
	key := []byte("test-key")
	err := Verify(key, nil)
	if err != nil {
		t.Errorf("empty log should verify ok, got: %v", err)
	}
}

func TestLogger_SequenceNumbers(t *testing.T) {
	var buf bytes.Buffer
	key := []byte("test-key")
	logger := New(key, &buf)

	logger.Log(EventSecretRead, "user1", "key1", "read", true, "")
	logger.Log(EventSecretRead, "user1", "key2", "read", true, "")
	logger.Log(EventSecretRead, "user1", "key3", "read", true, "")

	entries := parseEntries(t, buf.Bytes())

	if entries[0].ID != 1 || entries[1].ID != 2 || entries[2].ID != 3 {
		t.Error("sequence numbers not incrementing correctly")
	}
}

func parseEntries(t *testing.T, data []byte) []Entry {
	t.Helper()

	var entries []Entry
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("failed to parse entry: %v", err)
		}
		entries = append(entries, entry)
	}
	return entries
}
