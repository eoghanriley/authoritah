package authoritah

import "time"

// User represents an authenticated identity.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name,omitempty"`
	AvatarURL string    `json:"avatar_url,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents an active authenticated session.
type Session struct {
	ID        string         `json:"id"`
	UserID    string         `json:"user_id"`
	Token     string         `json:"token"`
	UserAgent string         `json:"user_agent"`
	IPAddress string         `json:"ip_address"`
	Meta      map[string]any `json:"meta,omitempty"`
	ExpiresAt time.Time      `json:"expires_at"`
	CreatedAt time.Time      `json:"created_at"`
}

// IsExpired reports whether the session has passed its expiry time.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
