# authoritah

A modular, plugin-based authentication library for Go HTTP services. Inspired by [Better Auth](https://better-auth.com), built for Go.

---

## Installation

```bash
go get github.com/you/authoritah
```

Requires Go 1.22 or later.

---

## Quick Start

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/you/authoritah/pkg/authoritah"
    "github.com/you/authoritah/pkg/plugins/credentials"
    "github.com/you/authoritah/pkg/plugins/oauth"
    "github.com/you/authoritah/pkg/adapters/gorm"
)

func main() {
    db := gorm.New(postgresDB)

    auth, err := authoritah.New(
        authoritah.WithDatabase(db),
        authoritah.WithConfig(authoritah.Config{
            BaseURL: "https://example.com",
        }),
        authoritah.WithPlugins(
            credentials.New(),
            oauth.New(oauth.WithProviders(
                oauth.NewGoogle(clientID, clientSecret, redirectURL),
            )),
        ),
    )
    if err != nil {
        log.Fatal(err)
    }

    if err := auth.Migrate(context.Background()); err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.Handle("/auth/", http.StripPrefix("/auth", auth))
    mux.Handle("/me", auth.RequireAuth(meHandler))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

---

## Configuration

`authoritah.New()` accepts functional options. All options are optional — sensible defaults apply where possible.

### `WithDatabase(db Database)`

Sets the database adapter. Required if you use `DatabaseStore` (the default session store) or any plugin that persists data.

```go
authoritah.WithDatabase(myAdapter)
```

### `WithSessionStore(s SessionStore)`

Overrides the default `DatabaseStore` with a custom `SessionStore` implementation. Useful for providing a `MemoryStore` in tests, or a Redis-backed store in production.

```go
// Development
authoritah.WithSessionStore(authoritah.NewMemoryStore(24 * time.Hour))

// Custom
authoritah.WithSessionStore(myRedisStore)
```

If `WithDatabase` is provided and `WithSessionStore` is not, a `DatabaseStore` is created automatically using `DefaultSessionDuration` (30 days).

### `WithPlugins(plugins ...Plugin)`

Registers one or more plugins. Plugins are initialized in registration order. Can be called multiple times.

```go
authoritah.WithPlugins(
    credentials.New(),
    oauth.New(...),
    totp.New(),
)
```

### `WithConfig(c Config)`

Sets top-level configuration values.

```go
authoritah.WithConfig(authoritah.Config{
    BaseURL:               "https://example.com",
    GooseMigrationDialect: "postgres",
})
```

| Field | Default | Description |
|---|---|---|
| `BaseURL` | `""` | Externally reachable root URL. Used by plugins to build callback URLs and magic links. |
| `GooseMigrationDialect` | `"postgres"` | SQL dialect for goose migrations. Accepted values: `"postgres"`, `"mysql"`, `"sqlite3"`. |

### `WithLogger(l *slog.Logger)`

Sets a custom structured logger. Defaults to `slog.Default()`.

```go
authoritah.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
```

---

## The Auth Struct

`Auth` is the central instance. After `New()` returns it is safe for concurrent use.

```go
auth, err := authoritah.New(opts...)
```

`New()` does the following in order:

1. Applies all options.
2. Sets defaults (logger, session store, migration dialect).
3. Calls `Init(a)` on each plugin in registration order.
4. Mounts each plugin's routes into an internal `http.ServeMux`.

If any plugin's `Init` returns an error, `New()` returns that error immediately and the `Auth` instance is nil.

### Accessor methods

```go
auth.DB()       Database      // the configured database adapter
auth.Sessions() SessionStore  // the configured session store
auth.Config()   Config        // top-level config
auth.Logger()   *slog.Logger  // the configured logger
```

### `auth.Plugin(id string) (Plugin, error)`

Retrieve a registered plugin by its ID. Returns `ErrPluginNotFound` if not registered. Useful when one part of your application needs to call plugin-specific methods directly.

```go
p, err := auth.Plugin("totp")
```

### `auth.Migrate(ctx context.Context) error`

Runs goose migrations for the core schema (`users`, `sessions`) and for every registered plugin that implements `Migrator`. Each gets its own tracking table, so version sequences are fully independent.

Call this once at startup, or drive it separately via the CLI (`authoritah migrate up`).

```go
if err := auth.Migrate(ctx); err != nil {
    log.Fatal(err)
}
```

### `auth.ServeHTTP(w, r)`

`Auth` implements `http.Handler`. Mount it into any router — see [Router Integration](#router-integration).

---

## Plugins

Every feature in authoritah is a plugin. The `Plugin` interface is the single contract all plugins must satisfy:

```go
type Plugin interface {
    ID() string          // stable snake_case slug, e.g. "oauth", "totp"
    Init(a *Auth) error  // called once by New(); receives *Auth
    Routes() []Route     // HTTP endpoints this plugin owns
}
```

Plugins that own database tables additionally implement `Migrator`:

```go
type Migrator interface {
    Migrations() *embed.FS  // embedded *.sql goose migration files
}
```

### Route

Each entry in `Routes()` describes one HTTP endpoint:

```go
type Route struct {
    Method  string       // "GET", "POST", etc.
    Path    string       // e.g. "/credentials/sign-in"
    Handler HandlerFunc
}

// HandlerFunc receives *Auth via closure so plugins stay net/http-compatible.
type HandlerFunc func(a *Auth) func(w http.ResponseWriter, r *http.Request)
```

Routes are mounted under whatever prefix you choose when mounting `auth` in your router. A route with `Path: "/credentials/sign-in"` mounted at `/auth` becomes `/auth/credentials/sign-in`.

### First-party plugins

| Package | ID | Description |
|---|---|---|
| `pkg/plugins/credentials` | `credentials` | Email + password sign-up, sign-in, sign-out |
| `pkg/plugins/oauth` | `oauth` | OAuth 2.0 social login (Google, and custom providers) |

See each plugin's own README for full documentation.

### Writing your own plugin

```go
type MyPlugin struct{}

func (p *MyPlugin) ID() string { return "myplugin" }

func (p *MyPlugin) Init(a *authoritah.Auth) error {
    a.RegisterHook(authoritah.HookAfterSignIn, p.onSignIn)
    return nil
}

func (p *MyPlugin) Routes() []authoritah.Route {
    return []authoritah.Route{
        {Method: "GET", Path: "/myplugin/ping", Handler: p.handlePing},
    }
}

func (p *MyPlugin) handlePing(_ *authoritah.Auth) func(http.ResponseWriter, *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }
}
```

If your plugin needs extra database tables, extend `authoritah.Database` with a sub-interface and assert it during `Init`:

```go
type MyDatabase interface {
    authoritah.Database
    GetWidgets(ctx context.Context, userID string) ([]*Widget, error)
}

func (p *MyPlugin) Init(a *authoritah.Auth) error {
    db, ok := a.DB().(MyDatabase)
    if !ok {
        return errors.New("myplugin: adapter does not implement MyDatabase")
    }
    p.db = db
    return nil
}
```

---

## Hooks

Hooks let application code and plugins react to auth lifecycle events without coupling to specific plugins. They are registered on `*Auth` and executed in registration order.

### Available hooks

| Constant | Fired by |
|---|---|
| `HookBeforeSignUp` | Before a new user is created |
| `HookAfterSignUp` | After a user and session are created |
| `HookBeforeSignIn` | Before credentials are verified |
| `HookAfterSignIn` | After a successful sign-in |
| `HookBeforeSignOut` | Before a session is revoked |
| `HookAfterSignOut` | After a session is revoked |

### Registering a hook

```go
auth.RegisterHook(authoritah.HookAfterSignUp, func(ctx context.Context, data authoritah.HookData) error {
    user := data["user"].(*authoritah.User)
    // send welcome email, provision a workspace, etc.
    return nil
})
```

`HookData` is `map[string]any`. The keys available at each event are documented in each plugin's README.

### Aborting with an error

Returning a non-nil error from a `Before*` hook aborts the operation entirely. The error message is returned to the caller as the HTTP response body.

```go
auth.RegisterHook(authoritah.HookBeforeSignIn, func(ctx context.Context, data authoritah.HookData) error {
    email := data["email"].(string)
    if isBlocked(email) {
        return errors.New("account suspended")
    }
    return nil
})
```

### Running hooks from a plugin

Plugins call `a.RunHooks()` from inside their handlers:

```go
if err := a.RunHooks(ctx, authoritah.HookBeforeSignIn, authoritah.HookData{
    "email": req.Email,
}); err != nil {
    httpError(w, err.Error(), http.StatusBadRequest)
    return
}
```

Hooks are goroutine-safe. `RegisterHook` and `RunHooks` use an internal `sync.RWMutex`.

---

## Session Management

Sessions are opaque tokens stored either in memory or in the database. The `SessionStore` interface abstracts all session operations:

```go
type SessionStore interface {
    Create(ctx context.Context, userID string, meta map[string]any) (*Session, error)
    Validate(ctx context.Context, token string) (*Session, error)
    Revoke(ctx context.Context, token string) error
    RevokeAll(ctx context.Context, userID string) error
}
```

### MemoryStore

Thread-safe, in-process store. Sessions are lost on restart. **Use only for development and tests.**

```go
authoritah.WithSessionStore(authoritah.NewMemoryStore(24 * time.Hour))
```

Passing `0` as the TTL uses `DefaultSessionDuration` (30 days).

### DatabaseStore

Persists sessions via the configured `Database` adapter. This is the default when `WithDatabase` is provided without `WithSessionStore`.

```go
// Created automatically, or explicitly:
authoritah.WithSessionStore(authoritah.NewDatabaseStore(db, 7*24*time.Hour))
```

### DefaultSessionDuration

```go
const DefaultSessionDuration = 30 * 24 * time.Hour
```

Used by both built-in stores when no TTL is specified.

### Implementing a custom SessionStore

Any struct that satisfies `SessionStore` can be passed to `WithSessionStore`. This is the extension point for Redis, JWT, or any other session backend.

---

## Middleware

### `auth.RequireAuth(next http.Handler) http.Handler`

Validates the session token from the request and injects the `*Session` into the request context. Returns `401 Unauthorized` if the token is missing, invalid, or expired.

Token lookup order:

1. `Authorization: Bearer <token>` header
2. `authoritah_session` cookie

```go
mux.Handle("/dashboard", auth.RequireAuth(dashboardHandler))
```

### `authoritah.GetSession(r *http.Request) *Session`

Package-level function. Retrieves the `*Session` injected by `RequireAuth`. Returns `nil` if called outside a `RequireAuth`-protected handler.

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    session := authoritah.GetSession(r)
    fmt.Fprintf(w, "user_id: %s", session.UserID)
}
```

### `auth.GetUser(r *http.Request) (*User, error)`

Loads the full `*User` for the session in the request context. Returns `ErrSessionNotFound` if there is no session, or a database error if the lookup fails. Must be called inside a `RequireAuth`-protected handler.

```go
func meHandler(w http.ResponseWriter, r *http.Request) {
    user, err := auth.GetUser(r)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(user)
}
```

---

## Database Interface

`Database` is the minimal interface a database adapter must satisfy. Plugins that need additional tables extend it with their own sub-interface.

```go
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

    // SQLDB returns the raw *sql.DB handle used by goose for migrations.
    SQLDB() *sql.DB
}
```

Database adapters live in `pkg/adapters/`. Pass one to `authoritah.WithDatabase()`.

---

## Core Schema

The core schema is managed by `migrations/00001_init.sql` and run when you call `auth.Migrate(ctx)`. It creates two tables:

**`users`**

| Column | Type | Notes |
|---|---|---|
| `id` | `TEXT` | Primary key, hex-encoded random bytes |
| `email` | `TEXT` | Unique, not null |
| `name` | `TEXT` | Display name, defaults to `''` |
| `avatar_url` | `TEXT` | Defaults to `''` |
| `created_at` | `TIMESTAMPTZ` | Set on insert |
| `updated_at` | `TIMESTAMPTZ` | Set on insert, updated by your adapter |

**`sessions`**

| Column | Type | Notes |
|---|---|---|
| `id` | `TEXT` | Primary key |
| `user_id` | `TEXT` | Foreign key → `users(id) ON DELETE CASCADE` |
| `token` | `TEXT` | Unique; 64-char hex string sent to clients |
| `expires_at` | `TIMESTAMPTZ` | Validated on every `Validate()` call |
| `created_at` | `TIMESTAMPTZ` | Set on insert |
| `meta` | `JSONB` | Arbitrary key/value set by the issuing plugin |

Indexed on `sessions(user_id)` and `sessions(token)`.

The goose tracking table for core migrations is `authoritah_migrations_core`.

---

## Models

### `User`

```go
type User struct {
    ID        string    `json:"id"`
    Email     string    `json:"email"`
    Name      string    `json:"name,omitempty"`
    AvatarURL string    `json:"avatar_url,omitempty"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### `Session`

```go
type Session struct {
    ID        string         `json:"id"`
    UserID    string         `json:"user_id"`
    Token     string         `json:"token"`
    ExpiresAt time.Time      `json:"expires_at"`
    CreatedAt time.Time      `json:"created_at"`
    Meta      map[string]any `json:"meta,omitempty"`
}
```

`Meta` is set by the plugin that issues the session. For example, the oauth plugin sets `meta["provider"] = "google"`.

#### `(s *Session) IsExpired() bool`

Reports whether the session's `ExpiresAt` is in the past. Called internally by both built-in session stores on every `Validate()`.

---

## Errors

All sentinel errors are defined in `errors.go` and can be compared with `errors.Is`:

| Variable | Value |
|---|---|
| `ErrSessionNotFound` | `"authoritah: session not found"` |
| `ErrSessionExpired` | `"authoritah: session expired"` |
| `ErrUserNotFound` | `"authoritah: user not found"` |
| `ErrUserAlreadyExists` | `"authoritah: user already exists"` |
| `ErrUnauthorized` | `"authoritah: unauthorized"` |
| `ErrPluginNotFound` | `"authoritah: plugin not found"` |

```go
user, err := auth.GetUser(r)
if errors.Is(err, authoritah.ErrSessionNotFound) {
    http.Error(w, "please sign in", http.StatusUnauthorized)
    return
}
```

---

## Router Integration

`Auth` implements `http.Handler` and works with any Go router.

**stdlib**
```go
http.Handle("/auth/", http.StripPrefix("/auth", auth))
```

**chi**
```go
r.Mount("/auth", auth)
```

**gorilla/mux**
```go
r.PathPrefix("/auth").Handler(http.StripPrefix("/auth", auth))
```

**gin**
```go
router.Any("/auth/*path", gin.WrapH(http.StripPrefix("/auth", auth)))
```

**echo**
```go
e.Any("/auth/*", echo.WrapHandler(http.StripPrefix("/auth", auth)))
```