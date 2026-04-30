package authoritah

import (
	"context"
	"embed"
)

// Plugin is the core interface every authoritah plugin must implement.
type Plugin interface {
	// ID returns a unique, stable snake_case identifier (e.g. "oauth", "totp").
	// Used as a namespace for migration tables, hook registration, and logging.
	ID() string

	// Init is called once during authoritah.New(). The plugin receives a
	// reference to the Auth instance so it can access the database, session
	// store, config, and register hooks.
	Init(a *Auth) error

	// Routes returns the HTTP routes this plugin wants to mount under /auth/.
	Routes() []Route
}

// Migrator is an optional interface plugins implement when they own database
// tables. The embedded FS should contain *.sql goose migration files.
type Migrator interface {
	Migrations(dialect string) (embed.FS, string)
}

// Route describes a single HTTP endpoint a plugin exposes.
type Route struct {
	Method      string // "GET", "POST", etc.
	Path        string // e.g. "/oauth/google/callback"
	Handler     HandlerFunc
	RequireAuth bool
}

// HandlerFunc is the standard handler signature used across authoritah.
// Plugins receive the Auth context via closure rather than a custom context
// type, keeping handlers compatible with net/http.
type HandlerFunc func(a *Auth) func(w ResponseWriter, r *Request)

// HookType identifies a lifecycle event plugins can subscribe to.
type HookType string

const (
	HookBeforeSignUp  HookType = "before_sign_up"
	HookAfterSignUp   HookType = "after_sign_up"
	HookBeforeSignIn  HookType = "before_sign_in"
	HookAfterSignIn   HookType = "after_sign_in"
	HookBeforeSignOut HookType = "before_sign_out"
	HookAfterSignOut  HookType = "after_sign_out"
)

// HookFunc is a callback invoked at a lifecycle event. Returning a non-nil
// error aborts the operation and propagates the error to the caller.
type HookFunc func(ctx context.Context, data HookData) error

// HookData carries event-specific context. Keys are documented per-hook.
type HookData map[string]any
