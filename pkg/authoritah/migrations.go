package authoritah

// CoreMigrations exposes the embedded core migration filesystem so the CLI
// (internal/migrate) can run them independently of a full Auth instance.
var CoreMigrations = coreMigrations
