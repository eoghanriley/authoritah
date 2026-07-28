package authoritah_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

func buildMiddlewareAuth(t *testing.T) (*authoritah.Auth, *authoritah.MemoryStore) {
	t.Helper()
	store := authoritah.NewMemoryStore(time.Hour)
	a, err := authoritah.New(authoritah.WithSessionStore(store))
	require.NoError(t, err)
	return a, store
}

func TestRequireAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		buildReq   func(token string) *http.Request
		wantStatus int
		wantReach  bool
	}{
		{
			name: "bearer token",
			buildReq: func(token string) *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name: "session cookie",
			buildReq: func(token string) *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: "authoritah_session", Value: token})
				return req
			},
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name: "no token",
			buildReq: func(_ string) *http.Request {
				return httptest.NewRequest("GET", "/", nil)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			buildReq: func(_ string) *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "Bearer not-a-real-token")
				return req
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "missing bearer prefix",
			buildReq: func(token string) *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", token) // no "Bearer " prefix
				return req
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, store := buildMiddlewareAuth(t)
			session, err := store.Create(context.Background(), "user-1", nil)
			require.NoError(t, err)

			reached := false
			handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, tt.buildReq(session.Token))

			require.Equal(t, tt.wantStatus, w.Code)
			require.Equal(t, tt.wantReach, reached)
		})
	}
}

func TestRequireAuth_InjectsSessionIntoContext(t *testing.T) {
	t.Parallel()

	a, store := buildMiddlewareAuth(t)
	session, err := store.Create(context.Background(), "user-1", nil)
	require.NoError(t, err)

	var gotSession *authoritah.Session
	handler := a.RequireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotSession = authoritah.GetSession(r)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, gotSession)
	require.Equal(t, session.Token, gotSession.Token)
}

func TestGetSession_OutsideMiddleware(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	require.Nil(t, authoritah.GetSession(req), "GetSession must return nil outside RequireAuth")
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupReq  func(store *authoritah.MemoryStore) *http.Request
		wantErr   bool
		wantEmail string
	}{
		{
			name: "success",
			setupReq: func(store *authoritah.MemoryStore) *http.Request {
				session, _ := store.Create(context.Background(), "user-1", nil)
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "Bearer "+session.Token)
				return req
			},
			wantEmail: "user@example.com",
		},
		{
			name: "no session in context",
			setupReq: func(_ *authoritah.MemoryStore) *http.Request {
				return httptest.NewRequest("GET", "/", nil)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db := newMockDB()
			store := authoritah.NewMemoryStore(time.Hour)
			user := &authoritah.User{ID: "user-1", Email: "user@example.com"}
			err := db.CreateUser(context.Background(), user)
			require.NoError(t, err)

			a, err := authoritah.New(
				authoritah.WithDatabase(db),
				authoritah.WithSessionStore(store),
			)
			require.NoError(t, err)

			req := tt.setupReq(store)

			var (
				gotUser *authoritah.User
				gotErr  error
			)
			handler := a.RequireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotUser, gotErr = a.GetUser(r)
			}))

			if tt.wantErr {
				// Call GetUser without going through RequireAuth.
				_, err := a.GetUser(req)
				require.ErrorIs(t, err, authoritah.ErrSessionNotFound)
				return
			}

			handler.ServeHTTP(httptest.NewRecorder(), req)
			require.NoError(t, gotErr)
			require.Equal(t, tt.wantEmail, gotUser.Email)
		})
	}
}
