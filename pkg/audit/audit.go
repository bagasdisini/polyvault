package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// EventType represents the type of audit event.
type EventType string

const (
	EventSecretRead   EventType = "secret.read"
	EventSecretWrite  EventType = "secret.write"
	EventSecretDelete EventType = "secret.delete"
	EventSecretList   EventType = "secret.list"
	EventSeal         EventType = "vault.seal"
	EventUnseal       EventType = "vault.unseal"
	EventTransitEnc   EventType = "transit.encrypt"
	EventTransitDec   EventType = "transit.decrypt"
)

// Entry represents a single audit log entry.
type Entry struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType EventType `json:"event_type"`
	Actor     string    `json:"actor"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Success   bool      `json:"success"`
	Details   string    `json:"details,omitempty"`
	Previous  []byte    `json:"previous"` // HMAC of previous entry
	HMAC      []byte    `json:"hmac"`     // HMAC of this entry
}

// Logger writes tamper-evident audit logs.
type Logger struct {
	mu     sync.Mutex
	key    []byte
	writer io.Writer
	last   []byte // HMAC of last entry
	seq    int
}

func New(key []byte, w io.Writer) *Logger {
	return &Logger{
		key:    key,
		writer: w,
		last:   make([]byte, 32),
	}
}

// Log records an audit event.
func (l *Logger) Log(eventType EventType, actor, resource, action string, success bool, details string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	entry := Entry{
		ID:        l.seq,
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Actor:     actor,
		Resource:  resource,
		Action:    action,
		Success:   success,
		Details:   details,
		Previous:  l.last,
	}

	// Compute HMAC of entry (excluding the HMAC field itself)
	entry.HMAC = l.computeHMAC(&entry)

	l.last = entry.HMAC
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: failed to marshal entry: %w", err)
	}

	data = append(data, '\n')
	if _, err := l.writer.Write(data); err != nil {
		return fmt.Errorf("audit: failed to write entry: %w", err)
	}

	return nil
}

func (l *Logger) computeHMAC(entry *Entry) []byte {
	mac := hmac.New(sha256.New, l.key)

	fmt.Fprintf(mac, "%d", entry.ID)
	mac.Write([]byte(entry.Timestamp.Format(time.RFC3339Nano)))
	mac.Write([]byte(entry.EventType))
	mac.Write([]byte(entry.Actor))
	mac.Write([]byte(entry.Resource))
	mac.Write([]byte(entry.Action))
	if entry.Success {
		mac.Write([]byte("true"))
	} else {
		mac.Write([]byte("false"))
	}
	mac.Write([]byte(entry.Details))
	mac.Write(entry.Previous)

	return mac.Sum(nil)
}

// Verify checks the integrity of a sequence of audit entries.
func Verify(key []byte, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	prev := make([]byte, 32)
	for i, entry := range entries {
		// Verify chain
		if !hmac.Equal(entry.Previous, prev) {
			return fmt.Errorf("audit: chain broken at entry %d", i+1)
		}

		expected := computeHMACForEntry(key, &entry)
		if !hmac.Equal(entry.HMAC, expected) {
			return fmt.Errorf("audit: HMAC mismatch at entry %d", i+1)
		}

		prev = entry.HMAC
	}

	return nil
}

func computeHMACForEntry(key []byte, entry *Entry) []byte {
	mac := hmac.New(sha256.New, key)

	fmt.Fprintf(mac, "%d", entry.ID)
	mac.Write([]byte(entry.Timestamp.Format(time.RFC3339Nano)))
	mac.Write([]byte(entry.EventType))
	mac.Write([]byte(entry.Actor))
	mac.Write([]byte(entry.Resource))
	mac.Write([]byte(entry.Action))
	if entry.Success {
		mac.Write([]byte("true"))
	} else {
		mac.Write([]byte("false"))
	}
	mac.Write([]byte(entry.Details))
	mac.Write(entry.Previous)

	return mac.Sum(nil)
}
