package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sqliteadapter "github.com/eoghanriley/authoritah/pkg/adapters/sqlite"
	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/oauth"
	"github.com/stretchr/testify/require"
)

// ---- oauthSQLiteDB ---------------------------------------------------------
//
// Wraps the SQLite adapter and adds the oauth.OAuthDatabase methods, operating
// directly on the oauth_accounts table created by the OAuth plugin's migration.

type oauthSQLiteDB struct {
	*sqliteadapter.Adapter
}

func (a *oauthSQLiteDB) GetOAuthAccount(ctx context.Context, provider, providerID string) (*oauth.Account, error) {
	row := a.SQLDB().QueryRowContext(ctx,
		`SELECT id, user_id, provider, provider_id, created_at
		 FROM oauth_accounts WHERE provider = ? AND provider_id = ?`,
		provider, providerID,
	)
	acc := &oauth.Account{}
	err := row.Scan(&acc.ID, &acc.UserID, &acc.Provider, &acc.ProviderID, &acc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authoritah.ErrUserNotFound
	}
	return acc, err
}

func (a *oauthSQLiteDB) CreateOAuthAccount(ctx context.Context, acc *oauth.Account) error {
	_, err := a.SQLDB().ExecContext(ctx,
		`INSERT INTO oauth_accounts (id, user_id, provider, provider_id) VALUES (?, ?, ?, ?)`,
		acc.ID, acc.UserID, acc.Provider, acc.ProviderID,
	)
	return err
}

func (a *oauthSQLiteDB) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*oauth.Account, error) {
	rows, err := a.SQLDB().QueryContext(ctx,
		`SELECT id, user_id, provider, provider_id, created_at FROM oauth_accounts WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*oauth.Account
	for rows.Next() {
		acc := &oauth.Account{}
		if err := rows.Scan(&acc.ID, &acc.UserID, &acc.Provider, &acc.ProviderID, &acc.CreatedAt); err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}

// ---- mockProvider ----------------------------------------------------------

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

// ---- HTTP helpers ----------------------------------------------------------

type sessionResp struct {
	Session *authoritah.Session `json:"session"`
	User    *authoritah.User    `json:"user"`
}

func credentialsSignUp(t *testing.T, a *authoritah.Auth, email, password string) sessionResp {
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

func credentialsSignIn(t *testing.T, a *authoritah.Auth, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest("POST", "/credentials/sign-in", bytes.NewReader(body))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

func credentialsSignOut(t *testing.T, a *authoritah.Auth, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/credentials/sign-out", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

// oauthGetState hits the redirect endpoint and returns the state cookie value.
func oauthGetState(t *testing.T, a *authoritah.Auth, provider string) string {
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
	t.Fatal("authoritah_oauth_state cookie not found")
	return ""
}

// oauthCallback submits the OAuth callback and returns the recorder.
func oauthCallback(a *authoritah.Auth, provider, state, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/oauth/%s/callback?code=%s&state=%s", provider, code, state), nil)
	req.AddCookie(&http.Cookie{Name: "authoritah_oauth_state", Value: state})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

// httpRequestJSON builds a POST request with a JSON body.
func httpRequestJSON(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return httptest.NewRequest(method, path, bytes.NewReader(b))
}

// newRecorder dispatches a request through auth and returns the response recorder.
func newRecorder(t *testing.T, a *authoritah.Auth, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}
