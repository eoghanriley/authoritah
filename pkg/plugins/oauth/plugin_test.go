package oauth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/oauth"
)

// ---- mock DB ---------------------------------------------------------------

type mockOAuthDB struct {
	users    map[string]*authoritah.User
	sessions map[string]*authoritah.Session
	accounts []*oauth.Account
}

func newMockOAuthDB() *mockOAuthDB {
	return &mockOAuthDB{
		users:    make(map[string]*authoritah.User),
		sessions: make(map[string]*authoritah.Session),
	}
}

func (m *mockOAuthDB) CreateUser(_ context.Context, u *authoritah.User) error {
	for _, e := range m.users {
		if e.Email == u.Email {
			return authoritah.ErrUserAlreadyExists
		}
	}
	m.users[u.ID] = u
	return nil
}
func (m *mockOAuthDB) GetUserByID(_ context.Context, id string) (*authoritah.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, authoritah.ErrUserNotFound
	}
	return u, nil
}
func (m *mockOAuthDB) GetUserByEmail(_ context.Context, email string) (*authoritah.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, authoritah.ErrUserNotFound
}
func (m *mockOAuthDB) UpdateUser(_ context.Context, u *authoritah.User) error {
	m.users[u.ID] = u
	return nil
}
func (m *mockOAuthDB) DeleteUser(_ context.Context, id string) error {
	delete(m.users, id)
	return nil
}
func (m *mockOAuthDB) CreateSession(_ context.Context, s *authoritah.Session) error {
	m.sessions[s.Token] = s
	return nil
}
func (m *mockOAuthDB) GetSession(_ context.Context, token string) (*authoritah.Session, error) {
	s, ok := m.sessions[token]
	if !ok {
		return nil, authoritah.ErrSessionNotFound
	}
	return s, nil
}
func (m *mockOAuthDB) DeleteSession(_ context.Context, token string) error {
	delete(m.sessions, token)
	return nil
}
func (m *mockOAuthDB) DeleteSessionsByUserID(_ context.Context, userID string) error {
	for tok, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, tok)
		}
	}
	return nil
}
func (m *mockOAuthDB) SQLDB() *sql.DB { return nil }

func (m *mockOAuthDB) GetOAuthAccount(_ context.Context, provider, providerID string) (*oauth.Account, error) {
	for _, a := range m.accounts {
		if a.Provider == provider && a.ProviderID == providerID {
			return a, nil
		}
	}
	return nil, authoritah.ErrUserNotFound
}
func (m *mockOAuthDB) CreateOAuthAccount(_ context.Context, a *oauth.Account) error {
	m.accounts = append(m.accounts, a)
	return nil
}
func (m *mockOAuthDB) GetOAuthAccountsByUserID(_ context.Context, userID string) ([]*oauth.Account, error) {
	var out []*oauth.Account
	for _, a := range m.accounts {
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// plainDB implements Database but NOT OAuthDatabase.
type plainDB struct{}

func (p *plainDB) CreateUser(_ context.Context, _ *authoritah.User) error { return nil }
func (p *plainDB) GetUserByID(_ context.Context, _ string) (*authoritah.User, error) {
	return nil, authoritah.ErrUserNotFound
}
func (p *plainDB) GetUserByEmail(_ context.Context, _ string) (*authoritah.User, error) {
	return nil, authoritah.ErrUserNotFound
}
func (p *plainDB) UpdateUser(_ context.Context, _ *authoritah.User) error       { return nil }
func (p *plainDB) DeleteUser(_ context.Context, _ string) error                 { return nil }
func (p *plainDB) CreateSession(_ context.Context, _ *authoritah.Session) error { return nil }
func (p *plainDB) GetSession(_ context.Context, _ string) (*authoritah.Session, error) {
	return nil, authoritah.ErrSessionNotFound
}
func (p *plainDB) DeleteSession(_ context.Context, _ string) error          { return nil }
func (p *plainDB) DeleteSessionsByUserID(_ context.Context, _ string) error { return nil }
func (p *plainDB) SQLDB() *sql.DB                                           { return nil }

// ---- mock provider ---------------------------------------------------------

type mockProvider struct {
	name string
	user *oauth.ProviderUser
	err  error
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) AuthURL(state string) string {
	return fmt.Sprintf("https://mock.example.com/oauth?provider=%s&state=%s", m.name, state)
}
func (m *mockProvider) Exchange(_ context.Context, _ string) (*oauth.ProviderUser, error) {
	return m.user, m.err
}

// ---- helpers ---------------------------------------------------------------

func buildOAuthAuth(t *testing.T, db *mockOAuthDB, providers ...oauth.Provider) *authoritah.Auth {
	t.Helper()
	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithSessionStore(authoritah.NewMemoryStore(time.Hour)),
		authoritah.WithPlugins(oauth.New(oauth.WithProviders(providers...))),
	)
	require.NoError(t, err)
	return a
}

// getState performs a redirect and returns the state cookie value.
func getState(t *testing.T, a *authoritah.Auth, provider string) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/oauth/"+provider, nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)
	for _, c := range w.Result().Cookies() {
		if c.Name == "authoritah_oauth_state" {
			return c.Value
		}
	}
	t.Fatal("authoritah_oauth_state cookie not found in redirect response")
	return ""
}

// doCallback submits an OAuth callback request.
func doCallback(a *authoritah.Auth, provider, state, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/oauth/%s/callback?code=%s&state=%s", provider, code, state), nil)
	req.AddCookie(&http.Cookie{Name: "authoritah_oauth_state", Value: state})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

// ---- TestInit --------------------------------------------------------------

func TestOAuth_Init(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		db      authoritah.Database
		wantErr bool
	}{
		{
			name:    "DB implements OAuthDatabase",
			db:      newMockOAuthDB(),
			wantErr: false,
		},
		{
			name:    "DB does not implement OAuthDatabase",
			db:      &plainDB{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := authoritah.New(
				authoritah.WithDatabase(tt.db),
				authoritah.WithSessionStore(authoritah.NewMemoryStore(time.Hour)),
				authoritah.WithPlugins(oauth.New()),
			)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ---- TestRedirect ----------------------------------------------------------

func TestOAuth_Redirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provider   string
		wantStatus int
	}{
		{name: "known provider redirects", provider: "mock", wantStatus: http.StatusTemporaryRedirect},
		{name: "unknown provider returns 400", provider: "unknown", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := buildOAuthAuth(t, newMockOAuthDB(), &mockProvider{name: "mock"})
			req := httptest.NewRequest("GET", "/oauth/"+tt.provider, nil)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)

			require.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestOAuth_Redirect_StateCookieProperties(t *testing.T) {
	t.Parallel()

	a := buildOAuthAuth(t, newMockOAuthDB(), &mockProvider{name: "mock"})
	req := httptest.NewRequest("GET", "/oauth/mock", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code)

	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "authoritah_oauth_state" {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "authoritah_oauth_state cookie must be set")
	require.NotEmpty(t, stateCookie.Value)
	require.True(t, stateCookie.HttpOnly)
	require.True(t, strings.Contains(w.Header().Get("Location"), stateCookie.Value),
		"redirect URL must contain the state value")
}

func TestOAuth_Redirect_UniqueStates(t *testing.T) {
	t.Parallel()

	a := buildOAuthAuth(t, newMockOAuthDB(), &mockProvider{name: "mock"})
	state1 := getState(t, a, "mock")
	state2 := getState(t, a, "mock")
	require.NotEqual(t, state1, state2, "each redirect must produce a unique state")
}

// ---- TestCallback ----------------------------------------------------------

func TestOAuth_Callback_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provider   string
		buildReq   func(a *authoritah.Auth, validState string) *http.Request
		wantStatus int
	}{
		{
			name:     "unknown provider",
			provider: "unknown",
			buildReq: func(_ *authoritah.Auth, state string) *http.Request {
				req := httptest.NewRequest("GET",
					"/oauth/unknown/callback?code=abc&state="+state, nil)
				req.AddCookie(&http.Cookie{Name: "authoritah_oauth_state", Value: state})
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:     "missing state cookie",
			provider: "mock",
			buildReq: func(_ *authoritah.Auth, _ string) *http.Request {
				return httptest.NewRequest("GET", "/oauth/mock/callback?code=abc&state=xyz", nil)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:     "state mismatch",
			provider: "mock",
			buildReq: func(_ *authoritah.Auth, _ string) *http.Request {
				req := httptest.NewRequest("GET", "/oauth/mock/callback?code=abc&state=wrong", nil)
				req.AddCookie(&http.Cookie{Name: "authoritah_oauth_state", Value: "correct"})
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:     "missing code",
			provider: "mock",
			buildReq: func(a *authoritah.Auth, _ string) *http.Request {
				state := getState(t, a, "mock")
				req := httptest.NewRequest("GET",
					fmt.Sprintf("/oauth/mock/callback?state=%s", state), nil)
				req.AddCookie(&http.Cookie{Name: "authoritah_oauth_state", Value: state})
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := buildOAuthAuth(t, newMockOAuthDB(), &mockProvider{name: "mock"})
			state := ""
			w := httptest.NewRecorder()
			a.ServeHTTP(w, tt.buildReq(a, state))

			require.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestOAuth_Callback_ExchangeError(t *testing.T) {
	t.Parallel()

	a := buildOAuthAuth(t, newMockOAuthDB(),
		&mockProvider{name: "mock", err: errors.New("exchange failed")})

	state := getState(t, a, "mock")
	w := doCallback(a, "mock", state, "bad-code")

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestOAuth_Callback_CreatesNewUser(t *testing.T) {
	t.Parallel()

	db := newMockOAuthDB()
	a := buildOAuthAuth(t, db, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-1", Email: "alice@example.com", Name: "Alice"},
	})

	state := getState(t, a, "mock")
	w := doCallback(a, "mock", state, "valid-code")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Session *authoritah.Session `json:"session"`
		User    *authoritah.User    `json:"user"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(t, "alice@example.com", resp.User.Email)
	require.Equal(t, "Alice", resp.User.Name)
	require.NotEmpty(t, resp.Session.Token)
	require.Len(t, db.accounts, 1)
	require.Equal(t, "prov-1", db.accounts[0].ProviderID)
}

func TestOAuth_Callback_LinksExistingEmailUser(t *testing.T) {
	t.Parallel()

	db := newMockOAuthDB()
	existing := &authoritah.User{ID: "user-existing", Email: "bob@example.com"}
	db.users[existing.ID] = existing

	a := buildOAuthAuth(t, db, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-bob", Email: "bob@example.com", Name: "Bob"},
	})

	state := getState(t, a, "mock")
	w := doCallback(a, "mock", state, "bob-code")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		User *authoritah.User `json:"user"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(t, "user-existing", resp.User.ID, "should return the existing user, not create a new one")
	require.Len(t, db.users, 1, "no new user should be created")
	require.Len(t, db.accounts, 1)
	require.Equal(t, "user-existing", db.accounts[0].UserID)
}

func TestOAuth_Callback_ReturnsExistingOAuthUser(t *testing.T) {
	t.Parallel()

	db := newMockOAuthDB()
	existing := &authoritah.User{ID: "user-carol", Email: "carol@example.com"}
	db.users[existing.ID] = existing
	db.accounts = []*oauth.Account{
		{ID: "acct-1", UserID: "user-carol", Provider: "mock", ProviderID: "prov-carol"},
	}

	a := buildOAuthAuth(t, db, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-carol", Email: "carol@example.com", Name: "Carol"},
	})

	state := getState(t, a, "mock")
	w := doCallback(a, "mock", state, "carol-code")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		User *authoritah.User `json:"user"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(t, "user-carol", resp.User.ID)
	require.Len(t, db.accounts, 1, "no duplicate OAuth account should be created")
}

func TestOAuth_Callback_SecondLoginNewSession(t *testing.T) {
	t.Parallel()

	db := newMockOAuthDB()
	a := buildOAuthAuth(t, db, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-dave", Email: "dave@example.com", Name: "Dave"},
	})

	state1 := getState(t, a, "mock")
	w1 := doCallback(a, "mock", state1, "code-1")
	require.Equal(t, http.StatusOK, w1.Code)

	state2 := getState(t, a, "mock")
	w2 := doCallback(a, "mock", state2, "code-2")
	require.Equal(t, http.StatusOK, w2.Code)

	var r1, r2 struct {
		Session *authoritah.Session `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w1.Body).Decode(&r1))
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&r2))
	require.NotEqual(t, r1.Session.Token, r2.Session.Token, "each login must issue a distinct session token")
}

func TestOAuth_Callback_MultipleProvidersOneUser(t *testing.T) {
	t.Parallel()

	db := newMockOAuthDB()
	a := buildOAuthAuth(t, db,
		&mockProvider{name: "google", user: &oauth.ProviderUser{ID: "g-1", Email: "eve@example.com", Name: "Eve"}},
		&mockProvider{name: "github", user: &oauth.ProviderUser{ID: "gh-1", Email: "eve@example.com", Name: "Eve"}},
	)

	state := getState(t, a, "google")
	require.Equal(t, http.StatusOK, doCallback(a, "google", state, "g-code").Code)

	state2 := getState(t, a, "github")
	require.Equal(t, http.StatusOK, doCallback(a, "github", state2, "gh-code").Code)

	require.Len(t, db.users, 1, "both providers should resolve to the same user via email")
	require.Len(t, db.accounts, 2, "each provider gets its own linked account")
}
