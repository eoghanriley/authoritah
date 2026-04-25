package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GoogleProvider implements Provider for Google OAuth 2.0.
type GoogleProvider struct {
	clientID     string
	clientSecret string
	redirectURL  string
}

// NewGoogle creates a Google OAuth provider.
func NewGoogle(clientID, clientSecret, redirectURL string) *GoogleProvider {
	return &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
}

func (g *GoogleProvider) Name() string { return "google" }

func (g *GoogleProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":     {g.clientID},
		"redirect_uri":  {g.redirectURL},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (g *GoogleProvider) Exchange(ctx context.Context, code string) (*ProviderUser, error) {
	// Exchange code for token
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"redirect_uri":  {g.redirectURL},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		return nil, fmt.Errorf("google: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("google: decode token response: %w", err)
	}

	// Fetch user info
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google: fetch userinfo: %w", err)
	}
	defer userResp.Body.Close()

	var userInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("google: decode userinfo: %w", err)
	}

	return &ProviderUser{
		ID:        userInfo.ID,
		Email:     strings.ToLower(userInfo.Email),
		Name:      userInfo.Name,
		AvatarURL: userInfo.Picture,
	}, nil
}
