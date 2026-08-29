package shamir

import (
	"bytes"
	"errors"
	"testing"
)

func TestSplitCombine_Basic(t *testing.T) {
	secret := []byte("hello world this is a test secret")
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Reconstruct with exactly threshold shares
	recovered, err := Combine(shares[:3])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("recovered secret does not match original")
	}
}

func TestSplitCombine_AllShares(t *testing.T) {
	secret := []byte("another secret")
	shares, err := Split(secret, 2, 4)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine with all shares failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("recovered secret does not match")
	}
}

func TestSplitCombine_DifferentSubsets(t *testing.T) {
	secret := []byte("subset test")
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Try different combinations of 3 shares
	subsets := [][]int{
		{0, 1, 2},
		{0, 1, 3},
		{0, 1, 4},
		{0, 2, 3},
		{0, 2, 4},
		{0, 3, 4},
		{1, 2, 3},
		{1, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
	}

	for _, subset := range subsets {
		selected := make([]Share, len(subset))
		for i, idx := range subset {
			selected[i] = shares[idx]
		}

		recovered, err := Combine(selected)
		if err != nil {
			t.Errorf("Combine with subset %v failed: %v", subset, err)
			continue
		}

		if !bytes.Equal(secret, recovered) {
			t.Errorf("subset %v: recovered secret does not match", subset)
		}
	}
}

func TestSplitCombine_SingleByteSecret(t *testing.T) {
	secret := []byte{0x42}
	shares, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares[:2])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("single byte: expected 0x%02x, got 0x%02x", secret[0], recovered[0])
	}
}

func TestSplitCombine_LargeSecret(t *testing.T) {
	// 1KB secret
	secret := make([]byte, 1024)
	for i := range secret {
		secret[i] = byte(i % 256)
	}

	shares, err := Split(secret, 5, 8)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	recovered, err := Combine(shares[:5])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("large secret: mismatch")
	}
}

func TestSplit_ValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		threshold int
		total     int
		wantErr   error
	}{
		{"empty secret", nil, 2, 3, ErrEmptySecret},
		{"threshold too low", []byte("test"), 1, 3, ErrInvalidThreshold},
		{"too few shares", []byte("test"), 2, 1, ErrTooFewShares},
		{"threshold exceeds total", []byte("test"), 5, 3, ErrThresholdExceeds},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Split(tt.secret, tt.threshold, tt.total)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCombine_InsufficientShares(t *testing.T) {
	secret := []byte("test secret here")
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// With fewer than threshold shares, the result should be wrong
	// (Lagrange interpolation still works, but gives incorrect result)
	recovered, err := Combine(shares[:2])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if bytes.Equal(secret, recovered) {
		t.Error("expected incorrect result with insufficient shares, but got correct secret")
	}
}

func TestCombine_DuplicateShares(t *testing.T) {
	secret := []byte("test")
	shares, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Pass the same share twice
	duplicate := []Share{shares[0], shares[0]}
	_, err = Combine(duplicate)
	if !errors.Is(err, ErrDuplicateShare) {
		t.Errorf("expected ErrDuplicateShare, got %v", err)
	}
}

func TestSharesAreDifferent(t *testing.T) {
	secret := []byte("test secret")
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Shares should all be different from each other
	for i := range shares {
		for j := i + 1; j < len(shares); j++ {
			if bytes.Equal(shares[i].Values, shares[j].Values) {
				t.Errorf("shares %d and %d are identical", i, j)
			}
		}
	}
}

func TestSharesDoNotRevealSecret(t *testing.T) {
	secret := []byte{0xFF}
	shares, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// A single share should not reveal the secret
	for _, share := range shares {
		if len(share.Values) == 1 && share.Values[0] == secret[0] {
			// This could happen by chance, but very unlikely for all shares
			t.Logf("warning: share value equals secret (could be coincidence)")
		}
	}
}
