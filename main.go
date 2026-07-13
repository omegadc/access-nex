// access-nex is an OAuth2 / OpenID Connect provider and management CLI.
//
// This file is the single program entry point. All real functionality lives
// in the internal packages:
//
//	internal/cli      — cobra command tree (user/app/provider/server commands)
//	internal/database — opens the SQLite database and creates the schema
//	internal/store    — SQL-backed CRUD for users, providers, applications
//	internal/server   — the HTTP OIDC/OAuth2 provider
//	internal/models   — shared data types
//	internal/secrets  — AES-GCM secret encryption + RSA signing key storage
package main

import (
	"log"

	"github.com/omegadc/access-nex/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		log.Fatal(err)
	}
}
