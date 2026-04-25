package authoritah

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SessionStore manages session lifecycle. Two implementations ship out of
// the box: MemoryStore (dev/test) and DatabaseStore (production). A JWT
// implementation is available as a plugin.
type SessionStore interface {
	Create(ctx context.Context, userID string, meta map[string]any) (*Session, error)
	Validate(ctx context.Context, token string) (*Session, error)
	Revoke(ctx context.Context, token string) error
	RevokeAll(ctx context.Context, userID string) error
}

// DefaultSessionDuration is used when no explicit TTL is configured.
const DefaultSessionDuration = 30 * 24 * time.Hour

// --- Memory Store ---------------------------------------------------

// MemoryStore is a thread-safe in-memory SessionStore for development
// and testing. Do not use in production — sessions are lost on restart.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewMemoryStore creates a MemoryStore with the given session TTL.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	if ttl == 0 {
		ttl = DefaultSessionDuration
	}
	return &MemoryStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

func (m *MemoryStore) Create(_ context.Context, userID string, meta map[string]any) (*Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("authoritah: generate session token: %w", err)
	}

	s := &Session{
		ID:        generateID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(m.ttl),
		CreatedAt: time.Now(),
		Meta:      meta,
	}

	m.mu.Lock()
	m.sessions[token] = s
	m.mu.Unlock()

	return s, nil
}

func (m *MemoryStore) Validate(_ context.Context, token string) (*Session, error) {
	m.mu.RLock()
	s, ok := m.sessions[token]
	m.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}
	if s.IsExpired() {
		m.mu.Lock()
		delete(m.sessions, token)
		m.mu.Unlock()
		return nil, ErrSessionExpired
	}
	return s, nil
}

func (m *MemoryStore) Revoke(_ context.Context, token string) error {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) RevokeAll(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, token)
		}
	}
	return nil
}

// --- Database Store -------------------------------------------------

// DatabaseStore persists sessions using the configured Database adapter.
type DatabaseStore struct {
	db  Database
	ttl time.Duration
}

// NewDatabaseStore creates a session store backed by the given Database.
func NewDatabaseStore(db Database, ttl time.Duration) *DatabaseStore {
	if ttl == 0 {
		ttl = DefaultSessionDuration
	}
	return &DatabaseStore{db: db, ttl: ttl}
}

func (d *DatabaseStore) Create(ctx context.Context, userID string, meta map[string]any) (*Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("authoritah: generate session token: %w", err)
	}

	s := &Session{
		ID:        generateID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(d.ttl),
		CreatedAt: time.Now(),
		Meta:      meta,
	}

	if err := d.db.CreateSession(ctx, s); err != nil {
		return nil, fmt.Errorf("authoritah: persist session: %w", err)
	}
	return s, nil
}

func (d *DatabaseStore) Validate(ctx context.Context, token string) (*Session, error) {
	s, err := d.db.GetSession(ctx, token)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if s.IsExpired() {
		_ = d.db.DeleteSession(ctx, token)
		return nil, ErrSessionExpired
	}
	return s, nil
}

func (d *DatabaseStore) Revoke(ctx context.Context, token string) error {
	return d.db.DeleteSession(ctx, token)
}

func (d *DatabaseStore) RevokeAll(ctx context.Context, userID string) error {
	return d.db.DeleteSessionsByUserID(ctx, userID)
}

// --- Helpers --------------------------------------------------------

func generateToken() (string, error) {
	b := make([]byte, 32)
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
