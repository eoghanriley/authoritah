package authoritah_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

func TestSession_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{name: "future expiry", expiresAt: time.Now().Add(time.Hour), want: false},
		{name: "past expiry", expiresAt: time.Now().Add(-time.Hour), want: true},
		{name: "zero time", expiresAt: time.Time{}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &authoritah.Session{ExpiresAt: tt.expiresAt}
			require.Equal(t, tt.want, s.IsExpired())
		})
	}
}

func TestMemoryStore_Create(t *testing.T) {
	t.Parallel()

	store := authoritah.NewMemoryStore(time.Hour)
	s, err := store.Create(context.Background(), "user-1", map[string]any{"role": "admin"})
	require.NoError(t, err)
	require.NotEmpty(t, s.ID)
	require.NotEmpty(t, s.Token)
	require.Equal(t, "user-1", s.UserID)
	require.Equal(t, "admin", s.Meta["role"])
	require.False(t, s.IsExpired())
}

func TestMemoryStore_Create_UniqueTokens(t *testing.T) {
	t.Parallel()

	store := authoritah.NewMemoryStore(time.Hour)
	s1, err := store.Create(context.Background(), "user-1", nil)
	require.NoError(t, err)
	s2, err := store.Create(context.Background(), "user-1", nil)
	require.NoError(t, err)
	require.NotEqual(t, s1.Token, s2.Token, "consecutive sessions must have distinct tokens")
}

func TestMemoryStore_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(store *authoritah.MemoryStore) string
		wantErr error
	}{
		{
			name: "valid token",
			setup: func(store *authoritah.MemoryStore) string {
				s, _ := store.Create(context.Background(), "user-1", nil)
				return s.Token
			},
		},
		{
			name: "nonexistent token",
			setup: func(_ *authoritah.MemoryStore) string {
				return "nonexistent"
			},
			wantErr: authoritah.ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := authoritah.NewMemoryStore(time.Hour)
			token := tt.setup(store)

			got, err := store.Validate(context.Background(), token)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, token, got.Token)
		})
	}
}

func TestMemoryStore_Validate_Expired(t *testing.T) {
	t.Parallel()

	store := authoritah.NewMemoryStore(time.Millisecond)
	s, err := store.Create(context.Background(), "user-1", nil)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	_, err = store.Validate(context.Background(), s.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionExpired, "expired session should return ErrSessionExpired")

	// Expired session is cleaned up; next call returns not found.
	_, err = store.Validate(context.Background(), s.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound, "cleaned-up session should return ErrSessionNotFound")
}

func TestMemoryStore_Revoke(t *testing.T) {
	t.Parallel()

	store := authoritah.NewMemoryStore(time.Hour)
	s, err := store.Create(context.Background(), "user-1", nil)
	require.NoError(t, err)

	require.NoError(t, store.Revoke(context.Background(), s.Token))

	_, err = store.Validate(context.Background(), s.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound)
}

func TestMemoryStore_Revoke_UnknownToken(t *testing.T) {
	t.Parallel()

	store := authoritah.NewMemoryStore(time.Hour)
	require.NoError(t, store.Revoke(context.Background(), "no-such-token"),
		"revoking an unknown token should not error")
}

func TestMemoryStore_RevokeAll(t *testing.T) {
	t.Parallel()

	store := authoritah.NewMemoryStore(time.Hour)
	s1, _ := store.Create(context.Background(), "user-1", nil)
	s2, _ := store.Create(context.Background(), "user-1", nil)
	s3, _ := store.Create(context.Background(), "user-2", nil)

	require.NoError(t, store.RevokeAll(context.Background(), "user-1"))

	_, err := store.Validate(context.Background(), s1.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound, "user-1 session 1 should be revoked")

	_, err = store.Validate(context.Background(), s2.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound, "user-1 session 2 should be revoked")

	_, err = store.Validate(context.Background(), s3.Token)
	require.NoError(t, err, "user-2 session should be unaffected")
}
