package authoritah_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

func TestSession_IsExpired_Future(t *testing.T) {
	s := &authoritah.Session{ExpiresAt: time.Now().Add(time.Hour)}
	if s.IsExpired() {
		t.Fatal("session with future expiry should not be expired")
	}
}

func TestSession_IsExpired_Past(t *testing.T) {
	s := &authoritah.Session{ExpiresAt: time.Now().Add(-time.Hour)}
	if !s.IsExpired() {
		t.Fatal("session with past expiry should be expired")
	}
}

func TestMemoryStore_Create(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	s, err := store.Create(context.Background(), "user-1", map[string]any{"role": "admin"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == "" {
		t.Error("want non-empty ID")
	}
	if s.Token == "" {
		t.Error("want non-empty Token")
	}
	if s.UserID != "user-1" {
		t.Errorf("want UserID %q, got %q", "user-1", s.UserID)
	}
	if s.Meta["role"] != "admin" {
		t.Errorf("want meta[role]=admin, got %v", s.Meta["role"])
	}
	if s.IsExpired() {
		t.Error("newly created session should not be expired")
	}
}

func TestMemoryStore_Create_UniqueTokens(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	s1, _ := store.Create(context.Background(), "user-1", nil)
	s2, _ := store.Create(context.Background(), "user-1", nil)
	if s1.Token == s2.Token {
		t.Error("consecutive sessions should have distinct tokens")
	}
}

func TestMemoryStore_Validate_Valid(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	created, _ := store.Create(context.Background(), "user-1", nil)

	got, err := store.Validate(context.Background(), created.Token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Token != created.Token {
		t.Errorf("want token %q, got %q", created.Token, got.Token)
	}
	if got.UserID != "user-1" {
		t.Errorf("want UserID %q, got %q", "user-1", got.UserID)
	}
}

func TestMemoryStore_Validate_NotFound(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	_, err := store.Validate(context.Background(), "nonexistent")
	if !errors.Is(err, authoritah.ErrSessionNotFound) {
		t.Errorf("want ErrSessionNotFound, got %v", err)
	}
}

func TestMemoryStore_Validate_Expired(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Millisecond)
	created, _ := store.Create(context.Background(), "user-1", nil)

	time.Sleep(10 * time.Millisecond)

	_, err := store.Validate(context.Background(), created.Token)
	if !errors.Is(err, authoritah.ErrSessionExpired) {
		t.Errorf("want ErrSessionExpired, got %v", err)
	}

	// Expired session is cleaned up; subsequent call returns not found.
	_, err = store.Validate(context.Background(), created.Token)
	if !errors.Is(err, authoritah.ErrSessionNotFound) {
		t.Errorf("want ErrSessionNotFound after expiry cleanup, got %v", err)
	}
}

func TestMemoryStore_Revoke(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	s, _ := store.Create(context.Background(), "user-1", nil)

	if err := store.Revoke(context.Background(), s.Token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := store.Validate(context.Background(), s.Token)
	if !errors.Is(err, authoritah.ErrSessionNotFound) {
		t.Errorf("want ErrSessionNotFound after revoke, got %v", err)
	}
}

func TestMemoryStore_Revoke_Unknown(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	if err := store.Revoke(context.Background(), "no-such-token"); err != nil {
		t.Errorf("revoking unknown token should not error, got %v", err)
	}
}

func TestMemoryStore_RevokeAll(t *testing.T) {
	store := authoritah.NewMemoryStore(time.Hour)
	s1, _ := store.Create(context.Background(), "user-1", nil)
	s2, _ := store.Create(context.Background(), "user-1", nil)
	s3, _ := store.Create(context.Background(), "user-2", nil)

	if err := store.RevokeAll(context.Background(), "user-1"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for _, tok := range []string{s1.Token, s2.Token} {
		if _, err := store.Validate(context.Background(), tok); !errors.Is(err, authoritah.ErrSessionNotFound) {
			t.Errorf("token %q: want ErrSessionNotFound, got %v", tok, err)
		}
	}

	if _, err := store.Validate(context.Background(), s3.Token); err != nil {
		t.Errorf("user-2 session should still be valid, got %v", err)
	}
}
