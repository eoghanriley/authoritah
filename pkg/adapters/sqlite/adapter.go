// Package sqlite provides a database/sql SQLite adapter for authoritah.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	_ "modernc.org/sqlite"
)

// Adapter implements authoritah.Database and credentials.CredentialsDatabase
// using a plain *sql.DB backed by SQLite.
type Adapter struct {
	db *sql.DB
}

// New wraps an already-opened *sql.DB.
func New(db *sql.DB) *Adapter {
	return &Adapter{db: db}
}

// Open is a convenience constructor that opens the SQLite file and returns
// a ready-to-use Adapter.
func Open(path string) (*Adapter, error) {
	db, err := sql.Open("sqlite", path+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("sqlite adapter: open: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("sqlite adapter: ping: %w", err)
	}
	return New(db), nil
}

func (a *Adapter) SQLDB() *sql.DB { return a.db }

// ---- Users ---------------------------------------------------------

func (a *Adapter) CreateUser(ctx context.Context, u *authoritah.User) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, avatar_url, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Name, u.AvatarURL, u.CreatedAt.UTC(), u.UpdatedAt.UTC(),
	)
	if err != nil {
		if isUniqueErr(err) {
			return authoritah.ErrUserAlreadyExists
		}
		return fmt.Errorf("sqlite: create user: %w", err)
	}
	return nil
}

func (a *Adapter) GetUserByID(ctx context.Context, id string) (*authoritah.User, error) {
	row := a.db.QueryRowContext(ctx,
		`SELECT id, email, name, avatar_url, created_at, updated_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (a *Adapter) GetUserByEmail(ctx context.Context, email string) (*authoritah.User, error) {
	row := a.db.QueryRowContext(ctx,
		`SELECT id, email, name, avatar_url, created_at, updated_at FROM users WHERE email = ?`, email)
	return scanUser(row)
}

func (a *Adapter) UpdateUser(ctx context.Context, u *authoritah.User) error {
	res, err := a.db.ExecContext(ctx,
		`UPDATE users SET email = ?, name = ?, avatar_url = ?, updated_at = ? WHERE id = ?`,
		u.Email, u.Name, u.AvatarURL, time.Now().UTC(), u.ID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: update user: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return authoritah.ErrUserNotFound
	}
	return nil
}

func (a *Adapter) DeleteUser(ctx context.Context, id string) error {
	res, err := a.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("sqlite: delete user: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return authoritah.ErrUserNotFound
	}
	return nil
}

// ---- Sessions ------------------------------------------------------

func (a *Adapter) CreateSession(ctx context.Context, s *authoritah.Session) error {
	meta, _ := json.Marshal(s.Meta)
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, token, user_agent, ip_address, meta, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.Token, s.UserAgent, s.IPAddress,
		string(meta), s.ExpiresAt.UTC(), s.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: create session: %w", err)
	}
	return nil
}

func (a *Adapter) GetSession(ctx context.Context, token string) (*authoritah.Session, error) {
	row := a.db.QueryRowContext(ctx,
		`SELECT id, user_id, token, user_agent, ip_address, meta, expires_at, created_at
         FROM sessions WHERE token = ?`, token)
	return scanSession(row)
}

func (a *Adapter) DeleteSession(ctx context.Context, token string) error {
	_, err := a.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (a *Adapter) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	_, err := a.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// ---- credentials.CredentialsDatabase ------------------------------

func (a *Adapter) SetPasswordHash(ctx context.Context, userID, hash string) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO user_credentials (user_id, hash) VALUES (?, ?)
         ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, updated_at = datetime('now')`,
		userID, hash,
	)
	if err != nil {
		return fmt.Errorf("sqlite: set password hash: %w", err)
	}
	return nil
}

func (a *Adapter) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	var hash string
	err := a.db.QueryRowContext(ctx,
		`SELECT hash FROM user_credentials WHERE user_id = ?`, userID,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", authoritah.ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("sqlite: get password hash: %w", err)
	}
	return hash, nil
}

// ---- Helpers -------------------------------------------------------

func scanUser(row *sql.Row) (*authoritah.User, error) {
	u := &authoritah.User{}
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authoritah.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: scan user: %w", err)
	}
	return u, nil
}

func scanSession(row *sql.Row) (*authoritah.Session, error) {
	s := &authoritah.Session{}
	var metaRaw string
	err := row.Scan(
		&s.ID, &s.UserID, &s.Token, &s.UserAgent, &s.IPAddress,
		&metaRaw, &s.ExpiresAt, &s.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authoritah.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: scan session: %w", err)
	}
	if metaRaw != "" && metaRaw != "{}" {
		_ = json.Unmarshal([]byte(metaRaw), &s.Meta)
	}
	return s, nil
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
