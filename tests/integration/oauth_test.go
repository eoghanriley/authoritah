package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/oauth"
)

func TestOAuth_CreatesNewUser(t *testing.T) {
	t.Parallel()

	a, db := buildOAuthAuth(t, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-1", Email: "alice@example.com", Name: "Alice"},
	})

	state := oauthGetState(t, a, "mock")
	w := oauthCallback(a, "mock", state, "code-1")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	got, err := db.GetUserByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "Alice", got.Name)

	acc, err := db.GetOAuthAccount(context.Background(), "mock", "prov-1")
	require.NoError(t, err)
	require.Equal(t, got.ID, acc.UserID, "OAuth account must be linked to the created user")
}

func TestOAuth_LinksExistingEmailUser(t *testing.T) {
	t.Parallel()

	a, db := buildOAuthAuth(t, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-bob", Email: "bob@example.com", Name: "Bob OAuth"},
	})
	ctx := context.Background()

	existing := &authoritah.User{
		ID:        "existing-bob",
		Email:     "bob@example.com",
		Name:      "Bob Credentials",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, db.CreateUser(ctx, existing))

	state := oauthGetState(t, a, "mock")
	w := oauthCallback(a, "mock", state, "bob-code")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	accounts, err := db.GetOAuthAccountsByUserID(ctx, "existing-bob")
	require.NoError(t, err)
	require.Len(t, accounts, 1, "one OAuth account must be linked to the existing user")
	require.Equal(t, "prov-bob", accounts[0].ProviderID)
}

func TestOAuth_ReturnsExistingAccountUser(t *testing.T) {
	t.Parallel()

	a, db := buildOAuthAuth(t, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-carol", Email: "carol@example.com", Name: "Carol"},
	})

	// First login — creates user + account.
	state1 := oauthGetState(t, a, "mock")
	require.Equal(t, http.StatusOK, oauthCallback(a, "mock", state1, "code-1").Code)

	user, err := db.GetUserByEmail(context.Background(), "carol@example.com")
	require.NoError(t, err)

	// Second login — must return same user, not create a duplicate account.
	state2 := oauthGetState(t, a, "mock")
	require.Equal(t, http.StatusOK, oauthCallback(a, "mock", state2, "code-2").Code)

	accounts, err := db.GetOAuthAccountsByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	require.Len(t, accounts, 1, "second login must not create a duplicate OAuth account")
}

func TestOAuth_SessionStoredInDB(t *testing.T) {
	t.Parallel()

	a, _ := buildOAuthAuth(t, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-dave", Email: "dave@example.com", Name: "Dave"},
	})

	state := oauthGetState(t, a, "mock")
	w := oauthCallback(a, "mock", state, "code-dave")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Session *authoritah.Session `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp.Session.Token)

	_, err := a.Sessions().Validate(context.Background(), resp.Session.Token)
	require.NoError(t, err, "session must be retrievable from the DB-backed store")
}

func TestOAuth_EachLoginProducesNewSession(t *testing.T) {
	t.Parallel()

	a, _ := buildOAuthAuth(t, &mockProvider{
		name: "mock",
		user: &oauth.ProviderUser{ID: "prov-eve", Email: "eve@example.com", Name: "Eve"},
	})

	state1 := oauthGetState(t, a, "mock")
	w1 := oauthCallback(a, "mock", state1, "code-1")
	require.Equal(t, http.StatusOK, w1.Code)

	state2 := oauthGetState(t, a, "mock")
	w2 := oauthCallback(a, "mock", state2, "code-2")
	require.Equal(t, http.StatusOK, w2.Code)

	var r1, r2 struct {
		Session *authoritah.Session `json:"session"`
	}
	require.NoError(t, json.NewDecoder(w1.Body).Decode(&r1))
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&r2))
	require.NotEqual(t, r1.Session.Token, r2.Session.Token, "each login must issue a distinct token")
}

func TestOAuth_MultipleProvidersSameUser(t *testing.T) {
	t.Parallel()

	a, db := buildOAuthAuth(t,
		&mockProvider{name: "google", user: &oauth.ProviderUser{ID: "g-frank", Email: "frank@example.com", Name: "Frank"}},
		&mockProvider{name: "github", user: &oauth.ProviderUser{ID: "gh-frank", Email: "frank@example.com", Name: "Frank"}},
	)
	ctx := context.Background()

	state := oauthGetState(t, a, "google")
	require.Equal(t, http.StatusOK, oauthCallback(a, "google", state, "g-code").Code)

	state2 := oauthGetState(t, a, "github")
	require.Equal(t, http.StatusOK, oauthCallback(a, "github", state2, "gh-code").Code)

	user, err := db.GetUserByEmail(ctx, "frank@example.com")
	require.NoError(t, err)

	accounts, err := db.GetOAuthAccountsByUserID(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, accounts, 2, "both providers must create separate OAuth accounts for the same user")
}
