package authoritah

import (
	"context"
	"database/sql"
)

// Database is the minimal interface the authoritah core requires.
// Adapters (gorm, sqlx, etc.) implement this. Plugins that need
// additional tables define their own sub-interface and assert it
// during Init.
type Database interface {
	// Users
	CreateUser(ctx context.Context, u *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error

	// Sessions
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, token string) (*Session, error)
	DeleteSession(ctx context.Context, token string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error

	// SQLDB returns the underlying *sql.DB so goose can run migrations.
	SQLDB() *sql.DB
}
