// Package authoritah provides a modular, plugin-based authentication library
// for Go HTTP services.
//
// "You will respect my authoritah!" — E. Cartman
//
// Usage:
//
//	auth, err := authoritah.New(
//	    authoritah.WithDatabase(db),
//	    authoritah.WithPlugins(credentials.New(), oauth.New(...)),
//	)
//	auth.Migrate(ctx)
//	r.Mount("/auth", auth)
package authoritah

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var coreMigrations embed.FS

// Auth is the central authoritah instance. Create one with New() and mount
// it into your router. Safe for concurrent use after initialization.
type Auth struct {
	db       Database
	sessions SessionStore
	plugins  []Plugin
	config   Config
	logger   *slog.Logger

	hooks   map[HookType][]HookFunc
	hooksMu sync.RWMutex

	mux *http.ServeMux
}

// Config holds top-level authoritah configuration.
type Config struct {
	// BaseURL is the externally reachable root of your app (e.g. https://example.com).
	// Used to construct OAuth callback URLs and magic link hrefs.
	BaseURL string

	// GooseMigrationDialect is the goose SQL dialect: "postgres", "mysql", "sqlite3".
	// Defaults to "postgres".
	GooseMigrationDialect string
}

// Option is a functional option for configuring Auth.
type Option func(*Auth)

// WithDatabase sets the database adapter.
func WithDatabase(db Database) Option {
	return func(a *Auth) { a.db = db }
}

// WithSessionStore overrides the default DatabaseStore.
func WithSessionStore(s SessionStore) Option {
	return func(a *Auth) { a.sessions = s }
}

// WithPlugins registers one or more plugins.
func WithPlugins(plugins ...Plugin) Option {
	return func(a *Auth) { a.plugins = append(a.plugins, plugins...) }
}

// WithConfig sets top-level configuration.
func WithConfig(c Config) Option {
	return func(a *Auth) { a.config = c }
}

// WithLogger sets a custom slog.Logger. Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(a *Auth) { a.logger = l }
}

// New creates and initializes an Auth instance. Plugins are initialized in
// registration order. Returns an error if any plugin's Init fails.
func New(opts ...Option) (*Auth, error) {
	a := &Auth{
		hooks: make(map[HookType][]HookFunc),
		mux:   http.NewServeMux(),
	}
	for _, o := range opts {
		o(a)
	}

	if a.logger == nil {
		a.logger = slog.Default()
	}
	if a.sessions == nil && a.db != nil {
		a.sessions = NewDatabaseStore(a.db, DefaultSessionDuration)
	}
	if a.config.GooseMigrationDialect == "" {
		a.config.GooseMigrationDialect = "postgres"
	}

	for _, p := range a.plugins {
		if err := p.Init(a); err != nil {
			return nil, fmt.Errorf("authoritah: init plugin %q: %w", p.ID(), err)
		}
		a.mountRoutes(p)
		a.logger.Info("authoritah: plugin initialized", "plugin", p.ID())
	}

	return a, nil
}

// ServeHTTP implements http.Handler. Mount under a path prefix:
//
//	r.Mount("/auth", auth)                                         // chi
//	http.Handle("/auth/", http.StripPrefix("/auth", auth))         // stdlib
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

// DB returns the configured database adapter.
func (a *Auth) DB() Database { return a.db }

// Sessions returns the configured session store.
func (a *Auth) Sessions() SessionStore { return a.sessions }

// Logger returns the configured logger.
func (a *Auth) Logger() *slog.Logger { return a.logger }

// Config returns top-level configuration.
func (a *Auth) Config() Config { return a.config }

// Plugin returns a registered plugin by ID, or ErrPluginNotFound.
func (a *Auth) Plugin(id string) (Plugin, error) {
	for _, p := range a.plugins {
		if p.ID() == id {
			return p, nil
		}
	}
	return nil, ErrPluginNotFound
}

// RegisterHook subscribes fn to a lifecycle event.
func (a *Auth) RegisterHook(hook HookType, fn HookFunc) {
	a.hooksMu.Lock()
	defer a.hooksMu.Unlock()
	a.hooks[hook] = append(a.hooks[hook], fn)
}

// RunHooks executes all registered hooks for an event in order.
// The first error aborts the chain.
func (a *Auth) RunHooks(ctx context.Context, hook HookType, data HookData) error {
	a.hooksMu.RLock()
	fns := a.hooks[hook]
	a.hooksMu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, data); err != nil {
			return err
		}
	}
	return nil
}

// Migrate runs goose migrations for the core schema and all plugins that
// implement Migrator. Each plugin gets its own tracking table so version
// sequences are fully independent.
func (a *Auth) Migrate(ctx context.Context) error {
	if err := a.runMigrations(ctx, "core", &coreMigrations); err != nil {
		return fmt.Errorf("authoritah: core migrations: %w", err)
	}
	for _, p := range a.plugins {
		m, ok := p.(Migrator)
		if !ok {
			continue
		}
		if err := a.runMigrations(ctx, p.ID(), m.Migrations()); err != nil {
			return fmt.Errorf("authoritah: plugin %q migrations: %w", p.ID(), err)
		}
	}
	return nil
}

func (a *Auth) runMigrations(ctx context.Context, pluginID string, fs *embed.FS) error {
	provider, err := goose.NewProvider(
		goose.Dialect(a.config.GooseMigrationDialect),
		a.db.SQLDB(),
		fs,
		goose.WithTableName("authoritah_migrations_"+pluginID),
	)
	if err != nil {
		return err
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return err
	}
	for _, r := range results {
		a.logger.Info("authoritah: migration applied",
			"plugin", pluginID,
			"version", r.Source.Version,
			"duration", r.Duration,
		)
	}
	return nil
}

func (a *Auth) mountRoutes(p Plugin) {
	for _, route := range p.Routes() {
		pattern := route.Method + " " + route.Path
		handler := route.Handler(a)
		a.mux.HandleFunc(pattern, handler)
		a.logger.Info("authoritah: route mounted", "plugin", p.ID(), "pattern", pattern)
	}
}
