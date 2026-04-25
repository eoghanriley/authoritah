# authoritah

**⚠️ This project is still heavily under development and not meant for any actual use in its current state**

> "You will respect my authoritah!" — Eric Cartman

A modular, plugin-based authentication library for Go backends. Inspired by [Better Auth](https://better-auth.com), built for Go.

## Features

- **Plugin-based** — only include what you need
- **Framework agnostic** — implements `http.Handler`, mounts anywhere
- **Goose migrations** — each plugin owns its schema, independently versioned
- **Hook system** — tap into lifecycle events across plugins
- **Bring your own database** — implement the `Database` interface

## Quick Start

```go
auth, err := authoritah.New(
    authoritah.WithDatabase(myDB),
    authoritah.WithConfig(authoritah.Config{
        BaseURL: "https://example.com",
    }),
    authoritah.WithPlugins(
        credentials.New(),
        oauth.New(
            oauth.WithProviders(
                oauth.NewGoogle(clientID, clientSecret, redirectURL),
            ),
        ),
    ),
)

// Run migrations once at startup
auth.Migrate(ctx)

// Mount under /auth
r.Mount("/auth", auth)

// Protect routes
r.Get("/me", auth.RequireAuth(meHandler))
```

## API Endpoints

| Method | Path                        | Plugin      | Description              |
|--------|-----------------------------|-------------|--------------------------|
| POST   | /auth/credentials/sign-up   | credentials | Register with email+pass |
| POST   | /auth/credentials/sign-in   | credentials | Sign in with email+pass  |
| POST   | /auth/credentials/sign-out  | credentials | Revoke session           |
| GET    | /auth/oauth/{provider}      | oauth       | Redirect to provider     |
| GET    | /auth/oauth/{provider}/callback | oauth   | Handle OAuth callback    |

## Plugins

| Plugin        | Description                        |
|---------------|------------------------------------|
| `credentials` | Email + password auth              |
| `oauth`       | Social login (Google, GitHub, ...) |

## Writing a Plugin

```go
type MyPlugin struct{}

func (p *MyPlugin) ID() string { return "myplugin" }

func (p *MyPlugin) Init(a *authoritah.Auth) error {
    // assert sub-interfaces, register hooks, etc.
    a.RegisterHook(authoritah.HookAfterSignIn, p.onSignIn)
    return nil
}

func (p *MyPlugin) Routes() []authoritah.Route {
    return []authoritah.Route{
        {Method: "GET", Path: "/myplugin/status", Handler: p.handleStatus},
    }
}

// Optional: ship your own migrations
//go:embed migrations/*.sql
var migrations embed.FS
func (p *MyPlugin) Migrations() *embed.FS { return &migrations }
```
