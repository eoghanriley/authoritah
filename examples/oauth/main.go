package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/eoghanriley/authoritah/pkg/adapters/sqlite"
	"github.com/eoghanriley/authoritah/pkg/authoritah"
	"github.com/eoghanriley/authoritah/pkg/plugins/oauth"
)

func main() {
	db, err := sqlite.Open("./authoritah-oauth.db")
	if err != nil {
		log.Fatal(err)
	}

	auth, err := authoritah.New(
		authoritah.WithDatabase(db),
		authoritah.WithConfig(authoritah.Config{
			BaseURL:               "http://localhost:8080",
			GooseMigrationDialect: "sqlite3",
		}),
		authoritah.WithPlugins(
			oauth.New(
				oauth.WithProviders(
					oauth.NewGitHub(
						os.Getenv("GITHUB_CLIENT_ID"),
						os.Getenv("GITHUB_CLIENT_SECRET"),
						"http://localhost:8080/auth/oauth/github/callback",
					),
				),
			),
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

	mux.Handle("/me", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.GetUser(r)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	})))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
