package authoritah_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
)

// buildMiddlewareAuth creates an Auth backed by a MemoryStore.
// Returns the auth and the store so tests can seed sessions directly.
func buildMiddlewareAuth(t *testing.T) (*authoritah.Auth, *authoritah.MemoryStore) {
	t.Helper()
	store := authoritah.NewMemoryStore(time.Hour)
	a, err := authoritah.New(authoritah.WithSessionStore(store))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return a, store
}

func TestRequireAuth_BearerToken(t *testing.T) {
	a, store := buildMiddlewareAuth(t)
	session, _ := store.Create(context.Background(), "user-1", nil)

	var gotSession *authoritah.Session
	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = authoritah.GetSession(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if gotSession == nil || gotSession.Token != session.Token {
		t.Error("expected session injected into context via GetSession")
	}
}

func TestRequireAuth_Cookie(t *testing.T) {
	a, store := buildMiddlewareAuth(t)
	session, _ := store.Create(context.Background(), "user-1", nil)

	reached := false
	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "authoritah_session", Value: session.Token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if !reached {
		t.Error("expected inner handler to be reached via cookie token")
	}
}

func TestRequireAuth_NoToken(t *testing.T) {
	a, _ := buildMiddlewareAuth(t)

	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	a, _ := buildMiddlewareAuth(t)

	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestRequireAuth_BearerPrefixRequired(t *testing.T) {
	a, store := buildMiddlewareAuth(t)
	session, _ := store.Create(context.Background(), "user-1", nil)

	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Token without "Bearer " prefix should be rejected.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", session.Token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without Bearer prefix, got %d", w.Code)
	}
}

func TestGetSession_OutsideRequireAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if s := authoritah.GetSession(req); s != nil {
		t.Errorf("expected nil session outside RequireAuth, got %v", s)
	}
}

func TestGetUser_Success(t *testing.T) {
	db := newMockDB()
	store := authoritah.NewMemoryStore(time.Hour)

	user := &authoritah.User{ID: "user-1", Email: "user@example.com"}
	_ = db.CreateUser(context.Background(), user)

	session, _ := store.Create(context.Background(), user.ID, nil)

	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithSessionStore(store),
	)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	var gotUser *authoritah.User
	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotUser, err = a.GetUser(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotUser == nil || gotUser.ID != user.ID {
		t.Errorf("want user ID %q, got %v", user.ID, gotUser)
	}
}

func TestGetUser_NoSession(t *testing.T) {
	a, err := authoritah.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	_, err = a.GetUser(req)
	if !errors.Is(err, authoritah.ErrSessionNotFound) {
		t.Errorf("want ErrSessionNotFound, got %v", err)
	}
}
