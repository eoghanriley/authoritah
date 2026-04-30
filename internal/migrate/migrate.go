// Package migrate contains the internal migration runner used by the CLI.
// It is not part of the public authoritah API.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/eoghanriley/authoritah/pkg/authoritah"
	_ "github.com/lib/pq" // postgres driver
	"github.com/pressly/goose/v3"
)

// Run executes a goose command ("up", "down", "status") against the given DSN.
// It runs core migrations only; plugin migrations are handled by Auth.Migrate()
// at application startup.
func Run(ctx context.Context, dsn, command string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	fsys, err := fs.Sub(authoritah.CoreMigrations("postgres"), "migrations/postgres")
	if err != nil {
		return fmt.Errorf("sub migrations fs: %w", err)
	}

	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		fsys,
		goose.WithTableName("authoritah_migrations_core"),
	)
	if err != nil {
		return err
	}

	switch command {
	case "up":
		_, err = provider.Up(ctx)
	case "down":
		_, err = provider.Down(ctx)
	case "status":
		results, e := provider.Status(ctx)
		if e != nil {
			return e
		}
		for _, r := range results {
			fmt.Printf("%-5s  v%d  %s\n", r.State, r.Source.Version, r.Source.Path)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q — use up, down, or status", command)
	}

	return err
}
