package authoritah_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

// ---- shared test doubles ---------------------------------------------------

type mockDB struct {
	users    map[string]*authoritah.User
	sessions map[string]*authoritah.Session
}

func newMockDB() *mockDB {
	return &mockDB{
		users:    make(map[string]*authoritah.User),
		sessions: make(map[string]*authoritah.Session),
	}
}

func (m *mockDB) CreateUser(_ context.Context, u *authoritah.User) error {
	m.users[u.ID] = u
	return nil
}
func (m *mockDB) GetUserByID(_ context.Context, id string) (*authoritah.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, authoritah.ErrUserNotFound
	}
	return u, nil
}
func (m *mockDB) GetUserByEmail(_ context.Context, email string) (*authoritah.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, authoritah.ErrUserNotFound
}
func (m *mockDB) UpdateUser(_ context.Context, u *authoritah.User) error {
	m.users[u.ID] = u
	return nil
}
func (m *mockDB) DeleteUser(_ context.Context, id string) error {
	delete(m.users, id)
	return nil
}
func (m *mockDB) CreateSession(_ context.Context, s *authoritah.Session) error {
	m.sessions[s.Token] = s
	return nil
}
func (m *mockDB) GetSession(_ context.Context, token string) (*authoritah.Session, error) {
	s, ok := m.sessions[token]
	if !ok {
		return nil, authoritah.ErrSessionNotFound
	}
	return s, nil
}
func (m *mockDB) DeleteSession(_ context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}
func (m *mockDB) DeleteSessionsByUserID(_ context.Context, userID string) error {
	for tok, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, tok)
		}
	}
	return nil
}
func (m *mockDB) SQLDB() *sql.DB { return nil }

type stubPlugin struct {
	id      string
	initErr error
}

func (s *stubPlugin) ID() string                    { return s.id }
func (s *stubPlugin) Routes() []authoritah.Route    { return nil }
func (s *stubPlugin) Init(_ *authoritah.Auth) error { return s.initErr }

// ---- TestNew ---------------------------------------------------------------

func TestNew_Defaults(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New()
	require.NoError(t, err)
	require.NotNil(t, a.Logger())
	require.Equal(t, "postgres", a.Config().GooseMigrationDialect)
}

func TestNew_WithOptions(t *testing.T) {
	t.Parallel()

	db := newMockDB()
	store := authoritah.NewMemoryStore(time.Hour)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := authoritah.Config{BaseURL: "https://example.com", GooseMigrationDialect: "sqlite3"}

	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithSessionStore(store),
		authoritah.WithLogger(logger),
		authoritah.WithConfig(cfg),
	)
	require.NoError(t, err)
	require.Equal(t, db, a.DB())
	require.Equal(t, store, a.Sessions())
	require.Equal(t, logger, a.Logger())
	require.Equal(t, "https://example.com", a.Config().BaseURL)
	require.Equal(t, "sqlite3", a.Config().GooseMigrationDialect)
}

func TestNew_DefaultSessionStore(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New(authoritah.WithDatabase(newMockDB()))
	require.NoError(t, err)
	require.NotNil(t, a.Sessions(), "expected DatabaseStore created automatically when db is set")
}

func TestNew_PluginInitFailure(t *testing.T) {
	t.Parallel()

	initErr := errors.New("init failed")
	_, err := authoritah.New(
		authoritah.WithPlugins(&stubPlugin{id: "bad", initErr: initErr}),
	)
	require.ErrorIs(t, err, initErr)
}

// ---- TestPlugin ------------------------------------------------------------

func TestPlugin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		lookupID  string
		wantErr   error
		wantFound bool
	}{
		{
			name:      "found",
			lookupID:  "my-plugin",
			wantFound: true,
		},
		{
			name:    "not found",
			lookupID: "nonexistent",
			wantErr: authoritah.ErrPluginNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, err := authoritah.New(
				authoritah.WithPlugins(&stubPlugin{id: "my-plugin"}),
			)
			require.NoError(t, err)

			p, err := a.Plugin(tt.lookupID)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.lookupID, p.ID())
		})
	}
}

// ---- TestHooks -------------------------------------------------------------

func TestHooks_RunInOrder(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New()
	require.NoError(t, err)

	var order []int
	a.RegisterHook(authoritah.HookAfterSignUp, func(_ context.Context, _ authoritah.HookData) error {
		order = append(order, 1)
		return nil
	})
	a.RegisterHook(authoritah.HookAfterSignUp, func(_ context.Context, _ authoritah.HookData) error {
		order = append(order, 2)
		return nil
	})

	require.NoError(t, a.RunHooks(context.Background(), authoritah.HookAfterSignUp, nil))
	require.Equal(t, []int{1, 2}, order)
}

func TestHooks_AbortOnError(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New()
	require.NoError(t, err)

	hookErr := errors.New("hook error")
	secondCalled := false

	a.RegisterHook(authoritah.HookBeforeSignUp, func(_ context.Context, _ authoritah.HookData) error {
		return hookErr
	})
	a.RegisterHook(authoritah.HookBeforeSignUp, func(_ context.Context, _ authoritah.HookData) error {
		secondCalled = true
		return nil
	})

	err = a.RunHooks(context.Background(), authoritah.HookBeforeSignUp, nil)
	require.ErrorIs(t, err, hookErr)
	require.False(t, secondCalled, "second hook must not run after first returns an error")
}

func TestHooks_NoHandlers(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New()
	require.NoError(t, err)

	require.NoError(t, a.RunHooks(context.Background(), authoritah.HookAfterSignIn, nil))
}

func TestHooks_DataPropagation(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New()
	require.NoError(t, err)

	var got authoritah.HookData
	a.RegisterHook(authoritah.HookAfterSignIn, func(_ context.Context, data authoritah.HookData) error {
		got = data
		return nil
	})

	require.NoError(t, a.RunHooks(context.Background(), authoritah.HookAfterSignIn, authoritah.HookData{"user_id": "u-1"}))
	require.Equal(t, "u-1", got["user_id"])
}

func TestHooks_IsolatedByType(t *testing.T) {
	t.Parallel()

	a, err := authoritah.New()
	require.NoError(t, err)

	called := false
	a.RegisterHook(authoritah.HookAfterSignUp, func(_ context.Context, _ authoritah.HookData) error {
		called = true
		return nil
	})

	require.NoError(t, a.RunHooks(context.Background(), authoritah.HookAfterSignIn, nil))
	require.False(t, called, "HookAfterSignUp must not fire for HookAfterSignIn")
}
