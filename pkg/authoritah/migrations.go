package authoritah

import "embed"

// CoreMigrations exposes the embedded migration filesystem for the CLI.
// Dialect must be "sqlite3" or "postgres".
func CoreMigrations(dialect string) embed.FS {
	switch dialect {
	case "sqlite3":
		return sqliteMigrations
	default:
		return postgresMigrations
	}
}
