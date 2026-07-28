package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

func TestCredentials_FullFlow(t *testing.T) {
	t.Parallel()

	a := buildCredentialsAuth(t)

	// Sign up.
	resp := credentialsSignUp(t, a, "alice@example.com", "securepass")
	require.Equal(t, "alice@example.com", resp.User.Email)
	require.NotEmpty(t, resp.Session.Token)

	// Sign in.
	w := credentialsSignIn(t, a, "alice@example.com", "securepass")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var signIn sessionResp
	require.NoError(t, json.NewDecoder(w.Body).Decode(&signIn))
	require.NotEmpty(t, signIn.Session.Token)

	// Sign out.
	wOut := credentialsSignOut(t, a, signIn.Session.Token)
	require.Equal(t, http.StatusNoContent, wOut.Code)

	// Revoked token must be rejected.
	w2 := credentialsSignOut(t, a, signIn.Session.Token)
	require.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestCredentials_SessionPersistedInDB(t *testing.T) {
	t.Parallel()

	a := buildCredentialsAuth(t)
	resp := credentialsSignUp(t, a, "bob@example.com", "mypassword")

	// Sign in to create a second session.
	credentialsSignIn(t, a, "bob@example.com", "mypassword")

	// The sign-up session must still be valid (DB-backed store, not ephemeral).
	wOut := credentialsSignOut(t, a, resp.Session.Token)
	require.Equal(t, http.StatusNoContent, wOut.Code, "sign-up session should remain valid after sign-in")
}

func TestCredentials_SignIn(t *testing.T) {
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
			name:       "correct credentials",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := buildCredentialsAuth(t)
			if tt.setupEmail != "" {
				credentialsSignUp(t, a, tt.setupEmail, tt.setupPass)
			}

			w := credentialsSignIn(t, a, tt.email, tt.password)
			require.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestCredentials_DuplicateEmail(t *testing.T) {
	t.Parallel()

	a := buildCredentialsAuth(t)
	credentialsSignUp(t, a, "dup@example.com", "pass1")

	w := credentialsSignIn(t, a, "dup@example.com", "pass1")
	require.Equal(t, http.StatusOK, w.Code)

	// Second sign-up with the same email must fail.
	req := httpRequestJSON(t, "POST", "/credentials/sign-up",
		map[string]string{"email": "dup@example.com", "password": "pass2"})
	w2 := newRecorder(t, a, req)
	require.Equal(t, http.StatusConflict, w2.Code)
}

func TestCredentials_SignOut_Unauthenticated(t *testing.T) {
	t.Parallel()

	a := buildCredentialsAuth(t)
	w := credentialsSignOut(t, a, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCredentials_MultipleUsers_IndependentSessions(t *testing.T) {
	t.Parallel()

	a := buildCredentialsAuth(t)
	r1 := credentialsSignUp(t, a, "user1@example.com", "pass1")
	r2 := credentialsSignUp(t, a, "user2@example.com", "pass2")

	require.NotEqual(t, r1.User.ID, r2.User.ID)
	require.NotEqual(t, r1.Session.Token, r2.Session.Token)

	// Sign out user1.
	require.Equal(t, http.StatusNoContent, credentialsSignOut(t, a, r1.Session.Token).Code)

	// user2's session must be unaffected.
	require.Equal(t, http.StatusNoContent, credentialsSignOut(t, a, r2.Session.Token).Code)
}

func TestCredentials_SignOut_InvalidatesSession(t *testing.T) {
	t.Parallel()

	a := buildCredentialsAuth(t)
	resp := credentialsSignUp(t, a, "frank@example.com", "pass")

	require.Equal(t, http.StatusNoContent, credentialsSignOut(t, a, resp.Session.Token).Code)

	_, err := a.Sessions().Validate(context.Background(), resp.Session.Token)
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound, "session must be removed from store after sign-out")
}
