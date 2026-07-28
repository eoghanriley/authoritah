package credentials_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/credentials"
)

// ---- mock DB ---------------------------------------------------------------

type mockCredDB struct {
	users    map[string]*authoritah.User
	sessions map[string]*authoritah.Session
	hashes   map[string]string
}

func newMockCredDB() *mockCredDB {
	return &mockCredDB{
		users:    make(map[string]*authoritah.User),
		sessions: make(map[string]*authoritah.Session),
		hashes:   make(map[string]string),
	}
}

func (m *mockCredDB) CreateUser(_ context.Context, u *authoritah.User) error {
	for _, existing := range m.users {
		if existing.Email == u.Email {
			return authoritah.ErrUserAlreadyExists
		}
	}
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

// ---- helpers ---------------------------------------------------------------

func buildAuth(t *testing.T) *authoritah.Auth {
	t.Helper()
	a, err := authoritah.New(
		authoritah.WithDatabase(newMockCredDB()),
		authoritah.WithSessionStore(authoritah.NewMemoryStore(time.Hour)),
		authoritah.WithPlugins(credentials.New(credentials.WithBcryptCost(4))),
	)
	require.NoError(t, err)
	return a
}

type sessionResp struct {
	Session *authoritah.Session `json:"session"`
	User    *authoritah.User    `json:"user"`
}

func signUp(t *testing.T, a *authoritah.Auth, email, password string) sessionResp {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest("POST", "/credentials/sign-up", bytes.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "sign-up failed: %s", w.Body.String())
	var resp sessionResp
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// ---- TestSignUp ------------------------------------------------------------

func TestSignUp_Success(t *testing.T) {
	t.Parallel()

	a := buildAuth(t)
	body := `{"email":"alice@example.com","password":"secret123","name":"Alice"}`
	req := httptest.NewRequest("POST", "/credentials/sign-up", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp sessionResp
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotNil(t, resp.User)
	require.Equal(t, "alice@example.com", resp.User.Email)
	require.Equal(t, "Alice", resp.User.Name)
	require.NotNil(t, resp.Session)
	require.NotEmpty(t, resp.Session.Token)
}

func TestSignUp_ValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "missing email", body: `{"email":"","password":"pass"}`},
		{name: "missing password", body: `{"email":"bob@example.com","password":""}`},
		{name: "invalid json", body: `not-json`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := buildAuth(t)
			req := httptest.NewRequest("POST", "/credentials/sign-up", bytes.NewBufferString(tt.body))
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)

			require.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestSignUp_DuplicateEmail(t *testing.T) {
	t.Parallel()

	a := buildAuth(t)
	signUp(t, a, "dup@example.com", "password1")

	body, _ := json.Marshal(map[string]string{"email": "dup@example.com", "password": "password2"})
	req := httptest.NewRequest("POST", "/credentials/sign-up", bytes.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusConflict, w.Code)
}

// ---- TestSignIn ------------------------------------------------------------

func TestSignIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setupEmail string
		setupPass  string
		email      string
		password   string
		wantStatus int
	}{
		{
			name:       "success",
			setupEmail: "carol@example.com",
			setupPass:  "mypassword",
			email:      "carol@example.com",
			password:   "mypassword",
			wantStatus: http.StatusOK,
		},
		{
			name:       "wrong password",
			setupEmail: "dave@example.com",
			setupPass:  "correcthorse",
			email:      "dave@example.com",
			password:   "wrongpassword",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unknown email",
			email:      "nobody@example.com",
			password:   "pass",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid json",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := buildAuth(t)
			if tt.setupEmail != "" {
				signUp(t, a, tt.setupEmail, tt.setupPass)
			}

			var body string
			if tt.name == "invalid json" {
				body = "not-json"
			} else {
				b, _ := json.Marshal(map[string]string{"email": tt.email, "password": tt.password})
				body = string(b)
			}

			req := httptest.NewRequest("POST", "/credentials/sign-in", bytes.NewBufferString(body))
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)

			require.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				var resp sessionResp
				require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
				require.NotEmpty(t, resp.Session.Token)
				require.Equal(t, tt.email, resp.User.Email)
			}
		})
	}
}

// ---- TestSignOut -----------------------------------------------------------

func TestSignOut_Success(t *testing.T) {
	t.Parallel()

	a := buildAuth(t)
	resp := signUp(t, a, "eve@example.com", "password")

	req := httptest.NewRequest("POST", "/credentials/sign-out", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Session.Token)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)

	_, err := a.Sessions().Validate(context.Background(), resp.Session.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound, "token must be invalid after sign-out")
}

func TestSignOut_Unauthenticated(t *testing.T) {
	t.Parallel()

	a := buildAuth(t)
	req := httptest.NewRequest("POST", "/credentials/sign-out", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---- TestHooks -------------------------------------------------------------

func TestSignUp_HookAbort(t *testing.T) {
	t.Parallel()

	a := buildAuth(t)
	a.RegisterHook(authoritah.HookBeforeSignUp, func(_ context.Context, data authoritah.HookData) error {
		if data["email"] == "blocked@example.com" {
			return &blockedError{}
		}
		return nil
	})

	body := `{"email":"blocked@example.com","password":"pass"}`
	req := httptest.NewRequest("POST", "/credentials/sign-up", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

type blockedError struct{}

func (e *blockedError) Error() string { return "email blocked" }
