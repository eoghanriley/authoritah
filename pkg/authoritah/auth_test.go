package authoritah_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

// mockDB is a minimal in-memory authoritah.Database for tests.
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

// stubPlugin is a no-op Plugin for testing.
type stubPlugin struct {
	id      string
	initErr error
}

func (s *stubPlugin) ID() string                    { return s.id }
func (s *stubPlugin) Routes() []authoritah.Route    { return nil }
func (s *stubPlugin) Init(_ *authoritah.Auth) error { return s.initErr }

func TestNew_Defaults(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if a.Logger() == nil {
		t.Error("expected default logger to be non-nil")
	}
	if a.Config().GooseMigrationDialect != "postgres" {
		t.Errorf("want default dialect %q, got %q", "postgres", a.Config().GooseMigrationDialect)
	}
}

func TestNew_WithOptions(t *testing.T) {
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
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	if a.DB() != db {
		t.Error("DB() should return the provided database")
	}
	if a.Sessions() != store {
		t.Error("Sessions() should return the provided session store")
	}
	if a.Logger() != logger {
		t.Error("Logger() should return the provided logger")
	}
	if a.Config().BaseURL != "https://example.com" {
		t.Errorf("Config().BaseURL: want %q, got %q", "https://example.com", a.Config().BaseURL)
	}
	if a.Config().GooseMigrationDialect != "sqlite3" {
		t.Errorf("Config().GooseMigrationDialect: want %q, got %q", "sqlite3", a.Config().GooseMigrationDialect)
	}
}

func TestNew_DefaultSessionStore(t *testing.T) {
	db := newMockDB()
	a, err := authoritah.New(authoritah.WithDatabase(db))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if a.Sessions() == nil {
		t.Error("expected a DatabaseStore to be created automatically when db is provided without a session store")
	}
}

func TestNew_PluginInitFailure(t *testing.T) {
	initErr := errors.New("init failed")
	_, err := authoritah.New(
		authoritah.WithPlugins(&stubPlugin{id: "bad", initErr: initErr}),
	)
	if err == nil {
		t.Fatal("expected error when plugin Init fails")
	}
	if !errors.Is(err, initErr) {
		t.Errorf("want wrapped initErr in error chain, got %v", err)
	}
}

func TestAuth_Plugin_Found(t *testing.T) {
	a, err := authoritah.New(
		authoritah.WithPlugins(&stubPlugin{id: "my-plugin"}),
	)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	p, err := a.Plugin("my-plugin")
	if err != nil {
		t.Fatalf("Plugin(): %v", err)
	}
	if p.ID() != "my-plugin" {
		t.Errorf("want ID %q, got %q", "my-plugin", p.ID())
	}
}

func TestAuth_Plugin_NotFound(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	_, err = a.Plugin("nonexistent")
	if !errors.Is(err, authoritah.ErrPluginNotFound) {
		t.Errorf("want ErrPluginNotFound, got %v", err)
	}
}

func TestAuth_Hooks_RunInOrder(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	var order []int
	a.RegisterHook(authoritah.HookAfterSignUp, func(_ context.Context, _ authoritah.HookData) error {
		order = append(order, 1)
		return nil
	})
	a.RegisterHook(authoritah.HookAfterSignUp, func(_ context.Context, _ authoritah.HookData) error {
		order = append(order, 2)
		return nil
	})

	if err := a.RunHooks(context.Background(), authoritah.HookAfterSignUp, nil); err != nil {
		t.Fatalf("RunHooks: %v", err)
	}
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Errorf("want hooks run in order [1 2], got %v", order)
	}
}

func TestAuth_Hooks_AbortOnError(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	hookErr := errors.New("hook error")
	secondCalled := false

	a.RegisterHook(authoritah.HookBeforeSignUp, func(_ context.Context, _ authoritah.HookData) error {
		return hookErr
	})
	a.RegisterHook(authoritah.HookBeforeSignUp, func(_ context.Context, _ authoritah.HookData) error {
		secondCalled = true
		return nil
	})

	if err := a.RunHooks(context.Background(), authoritah.HookBeforeSignUp, nil); !errors.Is(err, hookErr) {
		t.Errorf("want hookErr in error chain, got %v", err)
	}
	if secondCalled {
		t.Error("second hook should not run after first hook errors")
	}
}

func TestAuth_Hooks_NoHandlers(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if err := a.RunHooks(context.Background(), authoritah.HookAfterSignIn, nil); err != nil {
		t.Errorf("RunHooks with no handlers: want nil, got %v", err)
	}
}

func TestAuth_Hooks_DataPropagation(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	var got authoritah.HookData
	a.RegisterHook(authoritah.HookAfterSignIn, func(_ context.Context, data authoritah.HookData) error {
		got = data
		return nil
	})

	_ = a.RunHooks(context.Background(), authoritah.HookAfterSignIn, authoritah.HookData{"user_id": "u-1"})
	if got["user_id"] != "u-1" {
		t.Errorf("want data[user_id]=u-1, got %v", got["user_id"])
	}
}

func TestAuth_Hooks_IsolatedByType(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	called := false
	a.RegisterHook(authoritah.HookAfterSignUp, func(_ context.Context, _ authoritah.HookData) error {
		called = true
		return nil
	})

	_ = a.RunHooks(context.Background(), authoritah.HookAfterSignIn, nil)
	if called {
		t.Error("hook registered for AfterSignUp should not fire for AfterSignIn")
	}
}
