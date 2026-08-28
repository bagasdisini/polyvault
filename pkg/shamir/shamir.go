package shamir

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidThreshold = errors.New("shamir: threshold must be >= 2")
	ErrTooFewShares     = errors.New("shamir: must generate at least 2 shares")
	ErrThresholdExceeds = errors.New("shamir: threshold cannot exceed total shares")
	ErrEmptySecret      = errors.New("shamir: secret cannot be empty")
	ErrDuplicateShare   = errors.New("shamir: duplicate share IDs")
	ErrNotEnoughShares  = errors.New("shamir: not enough shares to reconstruct")
)

// Share represents a single share with an ID and value.
type Share struct {
	ID     byte
	Values []byte
}

// Split divides the secret into `total` shares where `threshold` are needed
// to reconstruct. Each byte of the secret is independently shared.
func Split(secret []byte, threshold, total int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if threshold < 2 {
		return nil, ErrInvalidThreshold
	}
	if total < 2 {
		return nil, ErrTooFewShares
	}
	if threshold > total {
		return nil, ErrThresholdExceeds
	}

	shares := make([]Share, total)
	for i := range shares {
		shares[i].ID = byte(i + 1)
		shares[i].Values = make([]byte, len(secret))
	}

	// For each byte position, generate a random polynomial and evaluate it
	for idx, s := range secret {
		poly, err := randomPolynomial(byte(s), threshold)
		if err != nil {
			return nil, fmt.Errorf("shamir: failed to generate polynomial: %w", err)
		}
		for i := range shares {
			shares[i].Values[idx] = polyEval(poly, shares[i].ID)
		}
	}

	return shares, nil
}

// Combine reconstructs the secret from the given shares using Lagrange interpolation.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrNotEnoughShares
	}

	// Check for duplicate share IDs
	seen := make(map[byte]bool)
	for _, s := range shares {
		if seen[s.ID] {
			return nil, ErrDuplicateShare
		}
		seen[s.ID] = true
	}

	// All shares must have the same length
	secretLen := len(shares[0].Values)
	for _, s := range shares[1:] {
		if len(s.Values) != secretLen {
			return nil, errors.New("shamir: share lengths do not match")
		}
	}

	secret := make([]byte, secretLen)
	for i := 0; i < secretLen; i++ {
		// Collect the (x, y) points for this byte position
		points := make([]struct{ x, y byte }, len(shares))
		for j, s := range shares {
			points[j] = struct{ x, y byte }{s.ID, s.Values[i]}
		}
		secret[i] = lagrangeInterpolate(points, 0)
	}

	return secret, nil
}
