# credentials

Email and password authentication plugin for authoritah.

Provides sign-up, sign-in, and sign-out endpoints. Passwords are hashed with [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt). Sessions are issued via authoritah's configured `SessionStore`.

---

## Installation

```go
import "github.com/eoghanriley/authoritah/pkg/plugins/credentials"
```

---

## Usage

```go
auth, err := authoritah.New(
    authoritah.WithDatabase(db),
    authoritah.WithPlugins(
        credentials.New(
            credentials.WithBcryptCost(12),
        ),
    ),
)
```

---

## Options

| Option | Default | Description |
|---|---|---|
| `WithBcryptCost(n int)` | `bcrypt.DefaultCost` (10) | bcrypt work factor. 12 is a reasonable production value. Higher = slower hashing. |

---

## HTTP Endpoints

All routes are mounted relative to wherever you mount the `Auth` handler. If you mount at `/auth`, the full paths become `/auth/credentials/sign-up`, etc.

### `POST /credentials/sign-up`

Register a new user with an email and password.

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "supersecret",
  "name": "Ada Lovelace"
}
```

`email` and `password` are required. `name` is optional.

**Success — `201 Created`:**

```json
{
  "session": {
    "id": "abc123",
    "user_id": "def456",
    "token": "64-char-hex-token",
    "expires_at": "2025-05-25T12:00:00Z"
  },
  "user": {
    "id": "def456",
    "email": "user@example.com",
    "name": "Ada Lovelace",
    "created_at": "2025-04-25T12:00:00Z"
  }
}
```

**Error responses:**

| Status | Body | Reason |
|---|---|---|
| `400` | `{"error": "email and password are required"}` | Missing field |
| `400` | `{"error": "..."}` | `HookBeforeSignUp` returned an error |
| `409` | `{"error": "email already in use"}` | Duplicate email |

---

### `POST /credentials/sign-in`

Sign in with an existing email and password.

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "supersecret"
}
```

**Success — `200 OK`:** Same shape as sign-up.

**Error responses:**

| Status | Body | Reason |
|---|---|---|
| `400` | `{"error": "..."}` | `HookBeforeSignIn` returned an error |
| `401` | `{"error": "invalid credentials"}` | Wrong email or password (response is identical regardless of which, to prevent user enumeration) |

---

### `POST /credentials/sign-out`

Revoke the current session. Requires an authenticated request (Bearer token or `authoritah_session` cookie).

**Request body:** None.

**Success — `204 No Content`**

**Error responses:**

| Status | Body | Reason |
|---|---|---|
| `401` | `{"error": "not authenticated"}` | No valid session on the request |

---

## Lifecycle Hooks

The credentials plugin fires the following authoritah hooks. Register them on the `Auth` instance to tap in:

| Hook | Fired | `HookData` keys |
|---|---|---|
| `HookBeforeSignUp` | Before the user is created | `"email" string` |
| `HookAfterSignUp` | After the user and session are created | `"user" *authoritah.User`, `"session" *authoritah.Session` |
| `HookBeforeSignIn` | Before credentials are checked | `"email" string` |
| `HookAfterSignIn` | After a successful sign-in | `"user" *authoritah.User`, `"session" *authoritah.Session` |
| `HookBeforeSignOut` | Before the session is revoked | `"session" *authoritah.Session` |
| `HookAfterSignOut` | After the session is revoked | `"session" *authoritah.Session` |

Returning a non-nil error from a `Before*` hook aborts the operation.

```go
// Example: block disposable email domains at sign-up
auth.RegisterHook(authoritah.HookBeforeSignUp, func(ctx context.Context, data authoritah.HookData) error {
    email := data["email"].(string)
    if strings.HasSuffix(email, "@mailinator.com") {
        return errors.New("disposable email addresses are not allowed")
    }
    return nil
})
```

---

## Database Adapter Requirements

Your database adapter must implement `credentials.CredentialsDatabase`, which extends `authoritah.Database` with two additional methods:

```go
type CredentialsDatabase interface {
    authoritah.Database
    SetPasswordHash(ctx context.Context, userID, hash string) error
    GetPasswordHash(ctx context.Context, userID string) (string, error)
}
```

The plugin asserts this interface during `Init` and returns a clear error at startup if it isn't satisfied — you won't be surprised at runtime.

---

## Schema

The plugin owns one table, managed by its embedded goose migration (`migrations/00001_create_credentials.sql`):

```sql
CREATE TABLE user_credentials (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Migrations run automatically when you call `auth.Migrate(ctx)`. The tracking table is `authoritah_migrations_credentials`, independent of all other plugins.

---

## Security Notes

- Passwords are never stored in plain text. Only the bcrypt hash is persisted.
- Sign-in returns an identical `401` whether the email doesn't exist or the password is wrong, preventing user enumeration.
- The bcrypt cost defaults to 10 (`bcrypt.DefaultCost`). For production, consider raising it to 12 — benchmark on your hardware to find a value that keeps hashing under ~100ms.