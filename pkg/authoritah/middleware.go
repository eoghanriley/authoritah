package authoritah

import (
	"context"
	"net/http"
)

type contextKey string

const sessionContextKey contextKey = "authoritah_session"

// RequireAuth is an http.Handler middleware that validates the session token
// from the Authorization header or the "authoritah_session" cookie.
// On success it injects the *Session into the request context.
// On failure it writes 401 and aborts.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := tokenFromRequest(r)
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		session, err := a.sessions.Validate(r.Context(), token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSession retrieves the *Session injected by RequireAuth.
// Returns nil if called outside of a RequireAuth-protected handler.
func GetSession(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionContextKey).(*Session)
	return s
}

// GetUser retrieves the full *User for the session in the request context.
// Returns ErrSessionNotFound if there is no session, or a database error
// if the user cannot be loaded.
func (a *Auth) GetUser(r *http.Request) (*User, error) {
	s := GetSession(r)
	if s == nil {
		return nil, ErrSessionNotFound
	}
	return a.db.GetUserByID(r.Context(), s.UserID)
}

func tokenFromRequest(r *http.Request) string {
	// 1. Bearer token in Authorization header
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	// 2. Cookie fallback
	if cookie, err := r.Cookie("authoritah_session"); err == nil {
		return cookie.Value
	}
	return ""
}
