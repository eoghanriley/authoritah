package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// --- Scopes ---------------------------------------------------------

// GitHubScope represents a GitHub OAuth permission scope.
type GitHubScope string

const (
	// GitHubScopeReadUser grants read access to a user's profile data.
	GitHubScopeReadUser GitHubScope = "read:user"
	// GitHubScopeUserEmail grants read access to a user's email addresses.
	GitHubScopeUserEmail GitHubScope = "user:email"
	// GitHubScopeRepo grants full access to public and private repositories.
	GitHubScopeRepo GitHubScope = "repo"
	// GitHubScopePublicRepo grants access to public repositories only.
	GitHubScopePublicRepo GitHubScope = "public_repo"
)

// --- Provider -------------------------------------------------------

// GitHubProvider implements Provider for GitHub OAuth 2.0.
type GitHubProvider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []GitHubScope
}

// GitHubOption is a functional option for configuring GitHubProvider.
type GitHubOption func(*GitHubProvider)

// WithGitHubScopes sets the OAuth scopes requested during authorization.
// Defaults to GitHubScopeReadUser and GitHubScopeUserEmail if not set.
func WithGitHubScopes(scopes ...GitHubScope) GitHubOption {
	return func(g *GitHubProvider) {
		g.scopes = scopes
	}
}

// NewGitHub creates a GitHub OAuth provider.
//
// clientID and clientSecret come from your GitHub OAuth App settings.
// redirectURL must match the callback URL registered with GitHub exactly.
//
// Example:
//
//	oauth.NewGitHub(
//	    os.Getenv("GITHUB_CLIENT_ID"),
//	    os.Getenv("GITHUB_CLIENT_SECRET"),
//	    "http://localhost:8080/auth/oauth/github/callback",
//	)
func NewGitHub(clientID, clientSecret, redirectURL string, opts ...GitHubOption) *GitHubProvider {
	g := &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       []GitHubScope{GitHubScopeReadUser, GitHubScopeUserEmail},
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// --- Provider interface ---------------------------------------------

func (g *GitHubProvider) Name() string { return "github" }

// AuthURL builds the GitHub authorization redirect URL.
func (g *GitHubProvider) AuthURL(state string) string {
	scopes := make([]string, len(g.scopes))
	for i, s := range g.scopes {
		scopes[i] = string(s)
	}
	params := url.Values{
		"client_id":    {g.clientID},
		"redirect_uri": {g.redirectURL},
		"scope":        {strings.Join(scopes, " ")},
		"state":        {state},
	}
	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

// Exchange converts a GitHub authorization code into a ProviderUser.
// It makes two requests: one to exchange the code for an access token,
// and one to fetch the user's profile from the GitHub API.
func (g *GitHubProvider) Exchange(ctx context.Context, code string) (*ProviderUser, error) {
	accessToken, err := g.fetchAccessToken(ctx, code)
	if err != nil {
		return nil, err
	}
	return g.fetchUser(ctx, accessToken)
}

// --- Private helpers ------------------------------------------------

// fetchAccessToken exchanges an authorization code for a GitHub access token.
func (g *GitHubProvider) fetchAccessToken(ctx context.Context, code string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://github.com/login/oauth/access_token",
		strings.NewReader(url.Values{
			"client_id":     {g.clientID},
			"client_secret": {g.clientSecret},
			"code":          {code},
			"redirect_uri":  {g.redirectURL},
		}.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("github: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("github: decode token response: %w", err)
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("github: token error: %s", tokenResp.Error)
	}
	return tokenResp.AccessToken, nil
}

// fetchUser retrieves the authenticated user's profile from the GitHub API.
// If the user's email is private, falls back to their noreply GitHub email.
func (g *GitHubProvider) fetchUser(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("github: build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: fetch user: %w", err)
	}
	defer resp.Body.Close()

	var userInfo struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("github: decode user: %w", err)
	}

	// GitHub users can set their email to private — fall back to their
	// noreply address so we always have something unique to store.
	email := strings.ToLower(userInfo.Email)
	if email == "" {
		email = strings.ToLower(userInfo.Login) + "@users.noreply.github.com"
	}

	return &ProviderUser{
		ID:        fmt.Sprintf("%d", userInfo.ID),
		Email:     email,
		Name:      userInfo.Name,
		AvatarURL: userInfo.AvatarURL,
	}, nil
}
