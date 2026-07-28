// Package integration contains integration tests that exercise the full stack
// against a real SQLite database. Run with:
//
//	go test -race -count=1 ./tests/integration/...
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	sqliteadapter "github.com/eoghanriley/authoritah/pkg/adapters/sqlite"
	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/credentials"
	"github.com/eoghanriley/authoritah/pkg/plugins/oauth"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// openSQLiteDB opens a fresh SQLite database in a temp directory.
func openSQLiteDB(t *testing.T) *sqliteadapter.Adapter {
	t.Helper()
	db, err := sqliteadapter.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err, "failed to open test SQLite DB")
	t.Cleanup(func() { db.SQLDB().Close() })
	return db
}

// buildCredentialsAuth creates a full Auth backed by real SQLite + credentials plugin.
func buildCredentialsAuth(t *testing.T) *authoritah.Auth {
	t.Helper()
	db := openSQLiteDB(t)
	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithConfig(authoritah.Config{GooseMigrationDialect: "sqlite3"}),
		authoritah.WithPlugins(credentials.New(credentials.WithBcryptCost(4))),
	)
	require.NoError(t, err)
	require.NoError(t, a.Migrate(context.Background()))
	return a
}

// buildOAuthAuth creates a full Auth backed by real SQLite + OAuth plugin.
func buildOAuthAuth(t *testing.T, providers ...oauth.Provider) (*authoritah.Auth, *oauthSQLiteDB) {
	t.Helper()
	base := openSQLiteDB(t)
	db := &oauthSQLiteDB{base}
	a, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithConfig(authoritah.Config{GooseMigrationDialect: "sqlite3"}),
		authoritah.WithPlugins(oauth.New(oauth.WithProviders(providers...))),
	)
	require.NoError(t, err)
	require.NoError(t, a.Migrate(context.Background()))
	return a, db
}
