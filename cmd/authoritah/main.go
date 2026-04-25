// Command authoritah provides a CLI for managing authoritah database migrations.
//
// Usage:
//
//	authoritah migrate up       Run all pending migrations
//	authoritah migrate down     Roll back the last migration
//	authoritah migrate status   Print migration status
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/eoghanriley/authoritah/internal/migrate"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "migrate" {
		fmt.Fprintln(os.Stderr, "usage: authoritah migrate <up|down|status>")
		os.Exit(1)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	ctx := context.Background()
	cmd := os.Args[2]

	if err := migrate.Run(ctx, dsn, cmd); err != nil {
		log.Fatalf("migrate %s: %v", cmd, err)
	}
}
