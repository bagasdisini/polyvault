package auth

import (
	"errors"
	"testing"
	"time"
)

func TestCreateToken(t *testing.T) {
	auth := New()

	rawToken, token, err := auth.CreateToken("test-token", []Policy{PolicyRead}, time.Hour)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	if rawToken == "" {
		t.Error("raw token is empty")
	}
	if token.Name != "test-token" {
		t.Errorf("expected name 'test-token', got '%s'", token.Name)
	}
}

func TestValidateToken(t *testing.T) {
	auth := New()

	rawToken, _, _ := auth.CreateToken("test", []Policy{PolicyRead}, time.Hour)

	token, err := auth.Validate(rawToken)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if token.Name != "test" {
		t.Errorf("expected name 'test', got '%s'", token.Name)
	}
}

func TestValidateToken_NotFound(t *testing.T) {
	auth := New()

	_, err := auth.Validate("nonexistent-token")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	auth := New()

	// Create token that expires immediately
	rawToken, _, _ := auth.CreateToken("test", []Policy{PolicyRead}, -time.Second)

	_, err := auth.Validate(rawToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRevokeToken(t *testing.T) {
	auth := New()

	rawToken, _, _ := auth.CreateToken("test", []Policy{PolicyRead}, time.Hour)

	err := auth.Revoke(rawToken)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	_, err = auth.Validate(rawToken)
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound after revoke, got %v", err)
	}
}

func TestRevokeToken_NotFound(t *testing.T) {
	auth := New()

	err := auth.Revoke("nonexistent")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestHasPolicy(t *testing.T) {
	token := &Token{
		Policies: []Policy{PolicyRead, PolicyWrite},
	}

	tests := []struct {
		policy Policy
		want   bool
	}{
		{PolicyRead, true},
		{PolicyWrite, true},
		{PolicyDelete, false},
		{PolicyAdmin, false},
	}

	for _, tt := range tests {
		got := token.HasPolicy(tt.policy)
		if got != tt.want {
			t.Errorf("HasPolicy(%s) = %v, want %v", tt.policy, got, tt.want)
		}
	}
}

func TestHasPolicy_Admin(t *testing.T) {
	token := &Token{
		Policies: []Policy{PolicyAdmin},
	}

	// Admin should have all permissions
	policies := []Policy{PolicyRead, PolicyWrite, PolicyDelete, PolicyList, PolicyTransit}
	for _, p := range policies {
		if !token.HasPolicy(p) {
			t.Errorf("admin should have %s policy", p)
		}
	}
}

func TestListTokens(t *testing.T) {
	auth := New()

	auth.CreateToken("token1", []Policy{PolicyRead}, time.Hour)
	auth.CreateToken("token2", []Policy{PolicyWrite}, time.Hour)

	tokens := auth.ListTokens()
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestCleanup(t *testing.T) {
	auth := New()

	// Create some expired and some valid tokens
	auth.CreateToken("expired1", []Policy{PolicyRead}, -time.Hour)
	auth.CreateToken("expired2", []Policy{PolicyRead}, -time.Minute)
	auth.CreateToken("valid", []Policy{PolicyRead}, time.Hour)

	removed := auth.Cleanup()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}

	tokens := auth.ListTokens()
	if len(tokens) != 1 {
		t.Errorf("expected 1 remaining token, got %d", len(tokens))
	}
}

func TestMultipleTokens(t *testing.T) {
	auth := New()

	tokens := make([]string, 10)
	for i := range 10 {
		raw, _, _ := auth.CreateToken("token", []Policy{PolicyRead}, time.Hour)
		tokens[i] = raw
	}

	// All tokens should be valid
	for i, raw := range tokens {
		_, err := auth.Validate(raw)
		if err != nil {
			t.Errorf("token %d validation failed: %v", i, err)
		}
	}
}
