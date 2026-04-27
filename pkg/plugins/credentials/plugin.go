// Package credentials provides email + password authentication for authoritah.
package credentials

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"golang.org/x/crypto/bcrypt"
)

//go:embed migrations/*.sql
var migrations embed.FS

// CredentialsDatabase extends authoritah.Database with password storage.
// Your adapter must implement this interface for the credentials plugin.
type CredentialsDatabase interface {
	authoritah.Database
	SetPasswordHash(ctx context.Context, userID, hash string) error
	GetPasswordHash(ctx context.Context, userID string) (string, error)
}

// Plugin implements email + password sign-up and sign-in.
type Plugin struct {
	db     CredentialsDatabase
	config Config
}

// Config holds credentials plugin options.
type Config struct {
	BcryptCost int
}

// Option is a functional option for the credentials plugin.
type Option func(*Plugin)

// WithBcryptCost sets the bcrypt work factor.
func WithBcryptCost(cost int) Option {
	return func(p *Plugin) { p.config.BcryptCost = cost }
}

// New creates a credentials plugin with the given options.
func New(opts ...Option) *Plugin {
	p := &Plugin{config: Config{BcryptCost: bcrypt.DefaultCost}}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *Plugin) ID() string           { return "credentials" }
func (p *Plugin) Migrations() embed.FS { return migrations }

func (p *Plugin) Init(a *authoritah.Auth) error {
	db, ok := a.DB().(CredentialsDatabase)
	if !ok {
		return errors.New("credentials: database adapter does not implement CredentialsDatabase")
	}
	p.db = db
	return nil
}

func (p *Plugin) Routes() []authoritah.Route {
	return []authoritah.Route{
		{Method: "POST", Path: "/credentials/sign-up", Handler: p.handleSignUp},
		{Method: "POST", Path: "/credentials/sign-in", Handler: p.handleSignIn},
		{Method: "POST", Path: "/credentials/sign-out", Handler: p.handleSignOut},
	}
}

type signUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type sessionResponse struct {
	Session *authoritah.Session `json:"session"`
	User    *authoritah.User    `json:"user"`
}

func (p *Plugin) handleSignUp(a *authoritah.Auth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signUpRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Email == "" || req.Password == "" {
			httpError(w, "email and password are required", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		if err := a.RunHooks(ctx, authoritah.HookBeforeSignUp, authoritah.HookData{"email": req.Email}); err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}

		if existing, _ := p.db.GetUserByEmail(ctx, req.Email); existing != nil {
			httpError(w, "email already in use", http.StatusConflict)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), p.config.BcryptCost)
		if err != nil {
			httpError(w, "internal error", http.StatusInternalServerError)
			return
		}

		user := &authoritah.User{ID: generateID(), Email: req.Email, Name: req.Name}
		if err := p.db.CreateUser(ctx, user); err != nil {
			httpError(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := p.db.SetPasswordHash(ctx, user.ID, string(hash)); err != nil {
			httpError(w, "internal error", http.StatusInternalServerError)
			return
		}

		session, err := a.Sessions().Create(ctx, user.ID, nil)
		if err != nil {
			httpError(w, "internal error", http.StatusInternalServerError)
			return
		}

		_ = a.RunHooks(ctx, authoritah.HookAfterSignUp, authoritah.HookData{"user": user, "session": session})
		writeJSON(w, http.StatusCreated, sessionResponse{Session: session, User: user})
	}
}

func (p *Plugin) handleSignIn(a *authoritah.Auth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signInRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		if err := a.RunHooks(ctx, authoritah.HookBeforeSignIn, authoritah.HookData{"email": req.Email}); err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}

		user, err := p.db.GetUserByEmail(ctx, req.Email)
		if err != nil {
			httpError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		hash, err := p.db.GetPasswordHash(ctx, user.ID)
		if err != nil {
			httpError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
			httpError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		session, err := a.Sessions().Create(ctx, user.ID, nil)
		if err != nil {
			httpError(w, "internal error", http.StatusInternalServerError)
			return
		}

		_ = a.RunHooks(ctx, authoritah.HookAfterSignIn, authoritah.HookData{"user": user, "session": session})
		writeJSON(w, http.StatusOK, sessionResponse{Session: session, User: user})
	}
}

func (p *Plugin) handleSignOut(a *authoritah.Auth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session := authoritah.GetSession(r)
		if session == nil {
			httpError(w, "not authenticated", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		_ = a.RunHooks(ctx, authoritah.HookBeforeSignOut, authoritah.HookData{"session": session})

		if err := a.Sessions().Revoke(ctx, session.Token); err != nil {
			httpError(w, "internal error", http.StatusInternalServerError)
			return
		}

		_ = a.RunHooks(ctx, authoritah.HookAfterSignOut, authoritah.HookData{"session": session})
		w.WriteHeader(http.StatusNoContent)
	}
}

func httpError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
