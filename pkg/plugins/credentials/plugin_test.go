package credentials_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/credentials"
)

// mockCredDB is an in-memory implementation of credentials.CredentialsDatabase.
type mockCredDB struct {
	users    map[string]*authoritah.User
	sessions map[string]*authoritah.Session
	hashes   map[string]string // userID -> bcrypt hash
}

func newMockCredDB() *mockCredDB {
	return &mockCredDB{
		users:    make(map[string]*authoritah.User),
		sessions: make(map[string]*authoritah.Session),
		hashes:   make(map[string]string),
	}
}

func (m *mockCredDB) CreateUser(_ context.Context, u *authoritah.User) error {
	m.users[u.ID] = u
	return nil
}

func (m *mockCredDB) GetUserByID(_ context.Context, id string) (*authoritah.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, authoritah.ErrUserNotFound
	}
	return u, nil
}

func (m *mockCredDB) GetUserByEmail(_ context.Context, email string) (*authoritah.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, authoritah.ErrUserNotFound
}

func (m *mockCredDB) UpdateUser(_ context.Context, u *authoritah.User) error {
	m.users[u.ID] = u
	return nil
}

func (m *mockCredDB) DeleteUser(_ context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func (m *mockCredDB) CreateSession(_ context.Context, s *authoritah.Session) error {
	m.sessions[s.Token] = s
	return nil
}

func (m *mockCredDB) GetSession(_ context.Context, token string) (*authoritah.Session, error) {
	s, ok := m.sessions[token]
	if !ok {
		return nil, authoritah.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockCredDB) DeleteSession(_ context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}

func (m *mockCredDB) DeleteSessionsByUserID(_ context.Context, userID string) error {
	for tok, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, tok)
		}
	}
	return nil
}

func (m *mockCredDB) SQLDB() *sql.DB { return nil }

func (m *mockCredDB) SetPasswordHash(_ context.Context, userID, hash string) error {
	m.hashes[userID] = hash
	return nil
}

func (m *mockCredDB) GetPasswordHash(_ context.Context, userID string) (string, error) {
	h, ok := m.hashes[userID]
	if !ok {
		return "", authoritah.ErrUserNotFound
	}
	return h, nil
}

// buildAuth creates an Auth with the credentials plugin backed by an in-memory store.
// BcryptCost 4 keeps tests fast.
func buildAuth(t *testing.T) (*authoritah.Auth, *mockCredDB) {
	t.Helper()
	db := newMockCredDB()
	store := authoritah.NewMemoryStore(time.Hour)
	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithSessionStore(store),
		authoritah.WithPlugins(credentials.New(credentials.WithBcryptCost(4))),
	)
	if err != nil {
		t.Fatalf("authoritah.New(): %v", err)
	}
	return a, db
}

type sessionResponse struct {
	Session *authoritah.Session `json:"session"`
	User    *authoritah.User    `json:"user"`
}

// signUp is a test helper that registers a user and asserts success.
func signUp(t *testing.T, a *authoritah.Auth, email, password string) sessionResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest("POST", "/credentials/sign-up", bytes.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("sign-up failed: %d %s", w.Code, w.Body.String())
	}
	var resp sessionResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	return resp
}

func TestSignUp_Success(t *testing.T) {
	a, _ := buildAuth(t)

	body := `{"email":"alice@example.com","password":"secret123","name":"Alice"}`
	req := httptest.NewRequest("POST", "/credentials/sign-up", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp sessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.User == nil || resp.User.Email != "alice@example.com" {
		t.Errorf("want email %q in response, got %v", "alice@example.com", resp.User)
	}
	if resp.User.Name != "Alice" {
		t.Errorf("want name %q, got %q", "Alice", resp.User.Name)
	}
	if resp.Session == nil || resp.Session.Token == "" {
		t.Error("expected non-empty session token in response")
	}
}

func TestSignUp_MissingEmail(t *testing.T) {
	a, _ := buildAuth(t)

	req := httptest.NewRequest("POST", "/credentials/sign-up", strings.NewReader(`{"email":"","password":"pass"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestSignUp_MissingPassword(t *testing.T) {
	a, _ := buildAuth(t)

	req := httptest.NewRequest("POST", "/credentials/sign-up", strings.NewReader(`{"email":"bob@example.com","password":""}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestSignUp_InvalidJSON(t *testing.T) {
	a, _ := buildAuth(t)

	req := httptest.NewRequest("POST", "/credentials/sign-up", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestSignUp_DuplicateEmail(t *testing.T) {
	a, _ := buildAuth(t)
	signUp(t, a, "dup@example.com", "password1")

	req := httptest.NewRequest("POST", "/credentials/sign-up", strings.NewReader(`{"email":"dup@example.com","password":"password2"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("want 409 for duplicate email, got %d", w.Code)
	}
}

func TestSignIn_Success(t *testing.T) {
	a, _ := buildAuth(t)
	signUp(t, a, "carol@example.com", "mypassword")

	req := httptest.NewRequest("POST", "/credentials/sign-in", strings.NewReader(`{"email":"carol@example.com","password":"mypassword"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp sessionResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Session == nil || resp.Session.Token == "" {
		t.Error("expected session token in sign-in response")
	}
	if resp.User == nil || resp.User.Email != "carol@example.com" {
		t.Errorf("want email %q in sign-in response, got %v", "carol@example.com", resp.User)
	}
}

func TestSignIn_WrongPassword(t *testing.T) {
	a, _ := buildAuth(t)
	signUp(t, a, "dave@example.com", "correcthorse")

	req := httptest.NewRequest("POST", "/credentials/sign-in", strings.NewReader(`{"email":"dave@example.com","password":"wrongpassword"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestSignIn_UnknownEmail(t *testing.T) {
	a, _ := buildAuth(t)

	req := httptest.NewRequest("POST", "/credentials/sign-in", strings.NewReader(`{"email":"nobody@example.com","password":"pass"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestSignIn_InvalidJSON(t *testing.T) {
	a, _ := buildAuth(t)

	req := httptest.NewRequest("POST", "/credentials/sign-in", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestSignOut_Success(t *testing.T) {
	a, _ := buildAuth(t)
	resp := signUp(t, a, "eve@example.com", "password")

	req := httptest.NewRequest("POST", "/credentials/sign-out", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Session.Token)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body.String())
	}

	// Token should no longer be valid.
	_, err := a.Sessions().Validate(context.Background(), resp.Session.Token)
	if !errors.Is(err, authoritah.ErrSessionNotFound) {
		t.Errorf("want ErrSessionNotFound after sign-out, got %v", err)
	}
}

func TestSignOut_Unauthenticated(t *testing.T) {
	a, _ := buildAuth(t)

	req := httptest.NewRequest("POST", "/credentials/sign-out", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for unauthenticated sign-out, got %d", w.Code)
	}
}

func TestSignUp_HookAbort(t *testing.T) {
	a, _ := buildAuth(t)
	a.RegisterHook(authoritah.HookBeforeSignUp, func(_ context.Context, data authoritah.HookData) error {
		if data["email"] == "blocked@example.com" {
			return &blockedError{}
		}
		return nil
	})

	req := httptest.NewRequest("POST", "/credentials/sign-up", strings.NewReader(`{"email":"blocked@example.com","password":"pass"}`))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 when before-sign-up hook rejects, got %d", w.Code)
	}
}

type blockedError struct{}

func (e *blockedError) Error() string { return "email blocked" }
