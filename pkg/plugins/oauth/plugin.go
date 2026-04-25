// Package oauth provides OAuth 2.0 social login for authoritah.
// Supports multiple providers — add providers via WithProviders().
package oauth

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/you/authoritah"
)

//go:embed migrations/*.sql
var migrations embed.FS

// OAuthDatabase extends authoritah.Database with OAuth account storage.
type OAuthDatabase interface {
	authoritah.Database
	GetOAuthAccount(ctx context.Context, provider, providerID string) (*Account, error)
	CreateOAuthAccount(ctx context.Context, a *Account) error
	GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*Account, error)
}

// Account represents a linked OAuth provider account.
type Account struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Provider     string    `json:"provider"`
	ProviderID   string    `json:"provider_id"`
	AccessToken  string    `json:"-"`
	RefreshToken string    `json:"-"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// Provider defines the interface a social login provider must implement.
type Provider interface {
	// Name returns a lowercase slug, e.g. "google", "github".
	Name() string
	// AuthURL builds the redirect URL to send the user to.
	AuthURL(state string) string
	// Exchange converts an authorization code into tokens and user info.
	Exchange(ctx context.Context, code string) (*ProviderUser, error)
}

// ProviderUser is the normalized user profile returned by a provider after OAuth.
type ProviderUser struct {
	ID        string
	Email     string
	Name      string
	AvatarURL string
}

// Plugin implements OAuth 2.0 sign-in for one or more providers.
type Plugin struct {
	db        OAuthDatabase
	providers map[string]Provider
}

// Option is a functional option for the OAuth plugin.
type Option func(*Plugin)

// WithProviders registers one or more OAuth providers.
func WithProviders(providers ...Provider) Option {
	return func(p *Plugin) {
		for _, provider := range providers {
			p.providers[provider.Name()] = provider
		}
	}
}

// New creates an OAuth plugin with the given options.
func New(opts ...Option) *Plugin {
	p := &Plugin{providers: make(map[string]Provider)}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *Plugin) ID() string            { return "oauth" }
func (p *Plugin) Migrations() *embed.FS { return &migrations }

func (p *Plugin) Init(a *authoritah.Auth) error {
	db, ok := a.DB().(OAuthDatabase)
	if !ok {
		return errors.New("oauth: database adapter does not implement OAuthDatabase")
	}
	p.db = db
	return nil
}

func (p *Plugin) Routes() []authoritah.Route {
	return []authoritah.Route{
		{Method: "GET", Path: "/oauth/{provider}", Handler: p.handleRedirect},
		{Method: "GET", Path: "/oauth/{provider}/callback", Handler: p.handleCallback},
	}
}

// handleRedirect redirects the user to the provider's authorization page.
func (p *Plugin) handleRedirect(_ *authoritah.Auth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		providerName := r.PathValue("provider")
		provider, ok := p.providers[providerName]
		if !ok {
			http.Error(w, fmt.Sprintf("unknown provider: %s", providerName), http.StatusBadRequest)
			return
		}

		state, err := generateState()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Store state in a short-lived cookie for CSRF protection
		http.SetCookie(w, &http.Cookie{
			Name:     "authoritah_oauth_state",
			Value:    state,
			MaxAge:   600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})

		http.Redirect(w, r, provider.AuthURL(state), http.StatusTemporaryRedirect)
	}
}

// handleCallback handles the provider redirect, exchanges the code, and
// creates or links the user account.
func (p *Plugin) handleCallback(a *authoritah.Auth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		providerName := r.PathValue("provider")
		provider, ok := p.providers[providerName]
		if !ok {
			http.Error(w, fmt.Sprintf("unknown provider: %s", providerName), http.StatusBadRequest)
			return
		}

		// Validate state
		stateCookie, err := r.Cookie("authoritah_oauth_state")
		if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "authoritah_oauth_state", MaxAge: -1})

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		providerUser, err := provider.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "failed to exchange code", http.StatusInternalServerError)
			return
		}

		// Find or create the user
		user, session, err := p.findOrCreateUser(ctx, a, providerName, providerUser)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session": session,
			"user":    user,
		})
	}
}

func (p *Plugin) findOrCreateUser(
	ctx context.Context,
	a *authoritah.Auth,
	providerName string,
	pu *ProviderUser,
) (*authoritah.User, *authoritah.Session, error) {
	// 1. Existing OAuth account?
	account, err := p.db.GetOAuthAccount(ctx, providerName, pu.ID)
	if err == nil {
		// Account exists — load the user and create a new session
		user, err := a.DB().GetUserByID(ctx, account.UserID)
		if err != nil {
			return nil, nil, err
		}
		session, err := a.Sessions().Create(ctx, user.ID, map[string]any{"provider": providerName})
		return user, session, err
	}

	// 2. User with matching email?
	user, err := a.DB().GetUserByEmail(ctx, pu.Email)
	if err != nil {
		// 3. Brand new user
		user = &authoritah.User{
			ID:        generateID(),
			Email:     pu.Email,
			Name:      pu.Name,
			AvatarURL: pu.AvatarURL,
		}
		if err := a.DB().CreateUser(ctx, user); err != nil {
			return nil, nil, fmt.Errorf("oauth: create user: %w", err)
		}
	}

	// Link the OAuth account
	if err := p.db.CreateOAuthAccount(ctx, &Account{
		ID:         generateID(),
		UserID:     user.ID,
		Provider:   providerName,
		ProviderID: pu.ID,
	}); err != nil {
		return nil, nil, fmt.Errorf("oauth: link account: %w", err)
	}

	session, err := a.Sessions().Create(ctx, user.ID, map[string]any{"provider": providerName})
	return user, session, err
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
