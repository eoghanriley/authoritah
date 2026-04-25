# oauth

OAuth 2.0 social login plugin for authoritah.

Handles the full authorization code flow: redirecting users to a provider, validating the CSRF state, exchanging the code for tokens, and finding or creating a linked user account. Multiple providers can be registered on a single plugin instance.

Ships with a [Google](#google) provider. Additional providers (GitHub, Discord, etc.) can be added by implementing the [`Provider`](#implementing-a-custom-provider) interface.

---

## Installation

```go
import "github.com/you/authoritah/pkg/plugins/oauth"
```

---

## Usage

```go
auth, err := authoritah.New(
    authoritah.WithDatabase(db),
    authoritah.WithPlugins(
        oauth.New(
            oauth.WithProviders(
                oauth.NewGoogle(
                    os.Getenv("GOOGLE_CLIENT_ID"),
                    os.Getenv("GOOGLE_CLIENT_SECRET"),
                    "https://example.com/auth/oauth/google/callback",
                ),
            ),
        ),
    ),
)
```

---

## Options

| Option | Description |
|---|---|
| `WithProviders(providers ...Provider)` | Register one or more OAuth providers. Can be called multiple times. |

---

## HTTP Endpoints

All routes are mounted relative to wherever you mount the `Auth` handler.

### `GET /oauth/{provider}`

Redirects the user to the provider's authorization page. Sets a short-lived `authoritah_oauth_state` cookie for CSRF protection (10 minute TTL, `HttpOnly`, `SameSite=Lax`).

**Path parameter:** `provider` — the slug returned by `Provider.Name()`, e.g. `google`.

**Success — `307 Temporary Redirect`** to the provider's auth URL.

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Unknown provider slug |

---

### `GET /oauth/{provider}/callback`

Handles the redirect back from the provider. Validates the state cookie, exchanges the authorization code for tokens, fetches the user's profile, then finds or creates a linked authoritah user and session.

**Query parameters:** `code`, `state` (both set by the provider).

**Find-or-create logic:**

1. Look up an existing `oauth_accounts` row for `(provider, provider_id)`. If found, load the user and issue a new session.
2. If no OAuth account exists, look for an authoritah user with a matching email. If found, link the new OAuth account to that user.
3. If no matching user at all, create a new user and link the OAuth account.

**Success — `200 OK`:**

```json
{
  "session": {
    "id": "abc123",
    "user_id": "def456",
    "token": "64-char-hex-token",
    "expires_at": "2025-05-25T12:00:00Z",
    "meta": { "provider": "google" }
  },
  "user": {
    "id": "def456",
    "email": "user@example.com",
    "name": "Ada Lovelace",
    "avatar_url": "https://lh3.googleusercontent.com/...",
    "created_at": "2025-04-25T12:00:00Z"
  }
}
```

**Error responses:**

| Status | Reason |
|---|---|
| `400` | Unknown provider, missing `code`, or state mismatch (CSRF) |
| `500` | Token exchange or user creation failed |

---

## Providers

### Google

```go
oauth.NewGoogle(clientID, clientSecret, redirectURL string) *GoogleProvider
```

Implements the Google OAuth 2.0 authorization code flow using the `openid email profile` scope. Fetches user info from `https://www.googleapis.com/oauth2/v2/userinfo`. Emails are normalized to lowercase.

**Setup:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials.
2. Create an OAuth 2.0 Client ID (Web application).
3. Add your redirect URI: `https://yourdomain.com/auth/oauth/google/callback`.
4. Copy the Client ID and Client Secret into your environment.

```go
oauth.NewGoogle(
    os.Getenv("GOOGLE_CLIENT_ID"),
    os.Getenv("GOOGLE_CLIENT_SECRET"),
    "https://yourdomain.com/auth/oauth/google/callback",
)
```

---

## Implementing a Custom Provider

Any struct that satisfies the `Provider` interface can be registered:

```go
type Provider interface {
    Name() string                                              // lowercase slug, e.g. "github"
    AuthURL(state string) string                               // redirect URL sent to the user
    Exchange(ctx context.Context, code string) (*ProviderUser, error) // code → user profile
}
```

`Exchange` must return a `*ProviderUser` with at minimum a unique `ID` and an `Email`:

```go
type ProviderUser struct {
    ID        string // provider's unique user ID
    Email     string // normalized to lowercase
    Name      string // optional display name
    AvatarURL string // optional profile picture URL
}
```

**Example — GitHub provider skeleton:**

```go
type GitHubProvider struct {
    clientID     string
    clientSecret string
    redirectURL  string
}

func NewGitHub(clientID, clientSecret, redirectURL string) *GitHubProvider {
    return &GitHubProvider{clientID, clientSecret, redirectURL}
}

func (g *GitHubProvider) Name() string { return "github" }

func (g *GitHubProvider) AuthURL(state string) string {
    params := url.Values{
        "client_id":    {g.clientID},
        "redirect_uri": {g.redirectURL},
        "scope":        {"read:user user:email"},
        "state":        {state},
    }
    return "https://github.com/login/oauth/authorize?" + params.Encode()
}

func (g *GitHubProvider) Exchange(ctx context.Context, code string) (*oauth.ProviderUser, error) {
    // 1. POST to https://github.com/login/oauth/access_token to get access token
    // 2. GET https://api.github.com/user with Authorization: Bearer <token>
    // 3. Return &oauth.ProviderUser{...}
}
```

Register it alongside other providers:

```go
oauth.New(
    oauth.WithProviders(
        oauth.NewGoogle(...),
        NewGitHub(...),
    ),
)
```

---

## Database Adapter Requirements

Your database adapter must implement `oauth.OAuthDatabase`, which extends `authoritah.Database` with three additional methods:

```go
type OAuthDatabase interface {
    authoritah.Database
    GetOAuthAccount(ctx context.Context, provider, providerID string) (*Account, error)
    CreateOAuthAccount(ctx context.Context, a *Account) error
    GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*Account, error)
}
```

The plugin asserts this interface during `Init` and returns a clear error at startup if it isn't satisfied.

---

## Schema

The plugin owns one table, managed by its embedded goose migration (`migrations/00001_create_oauth_accounts.sql`):

```sql
CREATE TABLE oauth_accounts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider, provider_id)
);
```

A single user can have multiple rows — one per linked provider. Migrations run automatically when you call `auth.Migrate(ctx)`. The tracking table is `authoritah_migrations_oauth`, independent of all other plugins.

---

## Security Notes

- **CSRF protection:** A random 32-byte state token is generated per-request and stored in an `HttpOnly`, `SameSite=Lax` cookie. The callback validates that the `state` query parameter matches before proceeding. The cookie is cleared immediately after validation.
- **Account linking by email:** If an OAuth provider returns an email that already exists in the `users` table, the OAuth account is linked to that existing user automatically. If your threat model requires stricter control over account linking (e.g., requiring the user to be signed in first), you should override this behaviour in your adapter or via a `HookBeforeSignIn`.
- **Tokens are not persisted** in the current implementation. If you need to store access or refresh tokens for calling provider APIs on behalf of users, extend the `oauth_accounts` table in a later migration and update your adapter.:w