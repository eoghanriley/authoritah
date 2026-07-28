package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/credentials"
)

// migrateCore runs only the core authoritah migrations (users + sessions tables).
func migrateCore(t *testing.T, db interface {
	authoritah.Database
}) {
	t.Helper()
	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithConfig(authoritah.Config{GooseMigrationDialect: "sqlite3"}),
	)
	require.NoError(t, err)
	require.NoError(t, a.Migrate(context.Background()))
}

// migrateWithCredentials runs core + credentials plugin migrations.
func migrateWithCredentials(t *testing.T, db interface {
	authoritah.Database
}) {
	t.Helper()
	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithConfig(authoritah.Config{GooseMigrationDialect: "sqlite3"}),
		authoritah.WithPlugins(credentials.New()),
	)
	require.NoError(t, err)
	require.NoError(t, a.Migrate(context.Background()))
}

func newTestUser(id, email string) *authoritah.User {
	now := time.Now().UTC().Truncate(time.Second)
	return &authoritah.User{ID: id, Email: email, Name: "Test User", CreatedAt: now, UpdatedAt: now}
}

// ---- User CRUD -------------------------------------------------------------

func TestSQLite_User_CreateAndGet(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	u := newTestUser("u-1", "alice@example.com")
	require.NoError(t, db.CreateUser(ctx, u))

	got, err := db.GetUserByID(ctx, "u-1")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", got.Email)
	require.Equal(t, "Test User", got.Name)
}

func TestSQLite_User_GetByEmail(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-2", "bob@example.com")))

	got, err := db.GetUserByEmail(ctx, "bob@example.com")
	require.NoError(t, err)
	require.Equal(t, "u-2", got.ID)
}

func TestSQLite_User_NotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		do   func(ctx context.Context, db authoritah.Database) error
	}{
		{
			name: "GetUserByID",
			do: func(ctx context.Context, db authoritah.Database) error {
				_, err := db.GetUserByID(ctx, "nonexistent")
				return err
			},
		},
		{
			name: "GetUserByEmail",
			do: func(ctx context.Context, db authoritah.Database) error {
				_, err := db.GetUserByEmail(ctx, "nobody@example.com")
				return err
			},
		},
		{
			name: "DeleteUser",
			do: func(ctx context.Context, db authoritah.Database) error {
				return db.DeleteUser(ctx, "nonexistent")
			},
		},
		{
			name: "UpdateUser",
			do: func(ctx context.Context, db authoritah.Database) error {
				return db.UpdateUser(ctx, newTestUser("nonexistent", "x@x.com"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := openSQLiteDB(t)
			migrateCore(t, db)
			err := tt.do(context.Background(), db)
			require.ErrorIs(t, err, authoritah.ErrUserNotFound)
		})
	}
}

func TestSQLite_User_DuplicateEmail(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-3a", "carol@example.com")))
	err := db.CreateUser(ctx, newTestUser("u-3b", "carol@example.com"))
	require.ErrorIs(t, err, authoritah.ErrUserAlreadyExists)
}

func TestSQLite_User_Update(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	u := newTestUser("u-4", "dave@example.com")
	require.NoError(t, db.CreateUser(ctx, u))

	u.Name = "Dave Updated"
	require.NoError(t, db.UpdateUser(ctx, u))

	got, err := db.GetUserByID(ctx, "u-4")
	require.NoError(t, err)
	require.Equal(t, "Dave Updated", got.Name)
}

func TestSQLite_User_Delete(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-5", "eve@example.com")))
	require.NoError(t, db.DeleteUser(ctx, "u-5"))

	_, err := db.GetUserByID(ctx, "u-5")
	require.ErrorIs(t, err, authoritah.ErrUserNotFound)
}

// ---- Session CRUD ----------------------------------------------------------

func newTestSession(id, userID, token string) *authoritah.Session {
	return &authoritah.Session{
		ID:        id,
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func TestSQLite_Session_CreateAndGet(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-s1", "frank@example.com")))

	s := newTestSession("sess-1", "u-s1", "tok-abc")
	s.Meta = map[string]any{"role": "admin"}
	require.NoError(t, db.CreateSession(ctx, s))

	got, err := db.GetSession(ctx, "tok-abc")
	require.NoError(t, err)
	require.Equal(t, "u-s1", got.UserID)
	require.Equal(t, "admin", got.Meta["role"])
}

func TestSQLite_Session_NotFound(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)

	_, err := db.GetSession(context.Background(), "no-such-token")
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound)
}

func TestSQLite_Session_Delete(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-s2", "grace@example.com")))
	require.NoError(t, db.CreateSession(ctx, newTestSession("sess-2", "u-s2", "tok-def")))
	require.NoError(t, db.DeleteSession(ctx, "tok-def"))

	_, err := db.GetSession(ctx, "tok-def")
	require.ErrorIs(t, err, authoritah.ErrSessionNotFound)
}

func TestSQLite_Session_DeleteByUserID(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateCore(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-s3", "henry@example.com")))
	require.NoError(t, db.CreateUser(ctx, newTestUser("u-s4", "iris@example.com")))
	require.NoError(t, db.CreateSession(ctx, newTestSession("sess-3a", "u-s3", "tok-1")))
	require.NoError(t, db.CreateSession(ctx, newTestSession("sess-3b", "u-s3", "tok-2")))
	require.NoError(t, db.CreateSession(ctx, newTestSession("sess-4", "u-s4", "tok-3")))

	require.NoError(t, db.DeleteSessionsByUserID(ctx, "u-s3"))

	for _, tok := range []string{"tok-1", "tok-2"} {
		_, err := db.GetSession(ctx, tok)
		require.ErrorIs(t, err, authoritah.ErrSessionNotFound, "u-s3 token %q should be deleted", tok)
	}
	_, err := db.GetSession(ctx, "tok-3")
	require.NoError(t, err, "u-s4 session must survive")
}

// ---- Password hash ---------------------------------------------------------

func TestSQLite_PasswordHash_SetAndGet(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateWithCredentials(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-pw", "jane@example.com")))
	require.NoError(t, db.SetPasswordHash(ctx, "u-pw", "hash-value"))

	got, err := db.GetPasswordHash(ctx, "u-pw")
	require.NoError(t, err)
	require.Equal(t, "hash-value", got)
}

func TestSQLite_PasswordHash_Upsert(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateWithCredentials(t, db)
	ctx := context.Background()

	require.NoError(t, db.CreateUser(ctx, newTestUser("u-pw2", "upsert@example.com")))
	require.NoError(t, db.SetPasswordHash(ctx, "u-pw2", "old-hash"))
	require.NoError(t, db.SetPasswordHash(ctx, "u-pw2", "new-hash"))

	got, err := db.GetPasswordHash(ctx, "u-pw2")
	require.NoError(t, err)
	require.Equal(t, "new-hash", got)
}

func TestSQLite_PasswordHash_NotFound(t *testing.T) {
	t.Parallel()

	db := openSQLiteDB(t)
	migrateWithCredentials(t, db)

	_, err := db.GetPasswordHash(context.Background(), "nonexistent")
	require.ErrorIs(t, err, authoritah.ErrUserNotFound)
}
