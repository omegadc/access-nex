# Access-Nex: OIDC/OAuth2 Provider

A self-hosted OpenID Connect (OIDC) and OAuth 2.0 provider with a management CLI. Register applications, manage users, and federate sign-in through external identity providers (Google, Microsoft, GitHub, Discord, Okta, or any custom OAuth2/OIDC provider). All data is stored in a SQLite database.

## Project Structure

```
access-nex/
├── main.go                     # Program entry point (starts the CLI)
├── go.mod / go.sum
├── internal/
│   ├── cli/cli.go              # Cobra command tree (user/app/provider/server)
│   ├── database/database.go    # Opens SQLite + creates the schema (users, providers, applications)
│   ├── store/                  # SQL CRUD layer
│   │   ├── store.go            #   shared helpers
│   │   ├── users.go            #   users table
│   │   ├── apps.go             #   applications table
│   │   └── providers.go        #   providers table (internal + external)
│   ├── server/                 # HTTP OIDC/OAuth2 provider
│   │   ├── server.go           #   routes, sessions, client/user authentication
│   │   ├── oidc.go             #   /authorize /token /userinfo /introspect /revoke /register ...
│   │   ├── proxy.go            #   external-provider SSO proxy (/oauth/start, /oauth/callback)
│   │   ├── web.go              #   home dashboard, login form, portal, apps page
│   │   └── helpers.go          #   JSON/PKCE/scope utilities
│   ├── models/models.go        # Shared types + built-in provider templates
│   └── secrets/secrets.go      # AES-GCM secret encryption, RSA signing key storage
└── .access-nex/                # Runtime data (gitignored)
    ├── access-nex.db           #   SQLite database
    ├── secret.key              #   AES key encrypting provider client secrets
    └── signing.pem             #   RSA key signing JWTs (stable across restarts)
```

## Database

The previous JSON files (`users.json`, `apps.json`, `providers.json`) are replaced by a SQLite database created automatically on first run ([internal/database/database.go](internal/database/database.go)). The driver is pure Go (`modernc.org/sqlite`) — no C compiler needed.

Three tables:

| Table          | Contents |
|----------------|----------|
| `users`        | Local accounts (bcrypt password hashes) and accounts auto-provisioned from external providers (`provider_id` + `external_id`) |
| `providers`    | One `internal` row for the local issuer, plus external OAuth2/OIDC providers with encrypted client secrets |
| `applications` | Registered OAuth2/OIDC clients: redirect URIs, scopes, public/confidential, optional link to an external provider |

## Quick Start

```bash
go build -o access-nex .

# 1. Initialize the local provider
./access-nex provider self init --issuer http://localhost:8080

# 2. Create a user
./access-nex user add -u alice -p secret123 -e alice@example.com -n "Alice Example"

# 3. Register an application
./access-nex app create -n "My App" -r http://localhost:9000/

# 4. (Optional) Add an external provider from a template
./access-nex provider add -n "Google SSO" -t google -c GOOGLE_CLIENT_ID -s GOOGLE_CLIENT_SECRET

# 5. Start the server
./access-nex server --addr :8080
```

Open http://localhost:8080 for the dashboard, or http://localhost:8080/login to sign in and get ready-to-paste OAuth client configuration (e.g. for Portainer).

## CLI Commands

| Command | Description |
|---------|-------------|
| `user add/list/delete` | Manage local users (passwords stored as bcrypt hashes) |
| `app create/list/show/update/delete` | Manage OAuth2/OIDC client applications |
| `provider self init/info` | Initialize/inspect the local OIDC provider |
| `provider add/list/show/update/delete` | Manage external providers (`-t google\|github\|microsoft\|discord\|okta\|custom`) |
| `server --addr :8080` | Run the HTTP provider |

All commands accept `--config DIR` (default `.access-nex`) to select the data directory.

## Server Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET/POST /authorize` | Authorization endpoint (login form + code issuance, PKCE) |
| `POST /token` | `authorization_code`, `refresh_token`, `client_credentials` grants |
| `GET /userinfo` | Claims for a bearer access token |
| `GET /jwks` | Public signing keys |
| `POST /introspect`, `/revoke` | RFC 7662 / 7009 |
| `POST /register` | RFC 7591 dynamic client registration (persisted to SQL) |
| `GET /oauth/providers` | List enabled external providers |
| `GET /oauth/start` | Begin SSO through an external provider |
| `GET /oauth/callback` | Provider callback → provisions user, issues local code |
| `GET /`, `/login`, `/portal`, `/apps` | Web UI |

### External provider flow

`/oauth/start?provider_id=X&client_id=Y&redirect_uri=Z` redirects the user to the external provider. After the user signs in, `/oauth/callback` exchanges the provider's code, fetches userinfo, creates (or finds) a row in the `users` table, and redirects back to the app with a **local** authorization code that the app exchanges at `/token` like any other login.

## Security Notes

Suitable for development and internal testing. Passwords are bcrypt-hashed, provider client secrets are AES-256-GCM encrypted at rest, and JWTs are RS256-signed with a persistent key — but access/refresh tokens and sessions live in memory (lost on restart), CORS is wide open, and there is no rate limiting or TLS termination. Put it behind HTTPS and harden before any production use.
