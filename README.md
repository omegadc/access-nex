# Access-Nex: OIDC/OAuth2 Provider

A self-hosted OpenID Connect (OIDC) and OAuth 2.0 provider with a management CLI. Register applications, manage users, and federate sign-in through external identity providers (Google, Microsoft, GitHub, Discord, Okta, or any custom OAuth2/OIDC provider). Data is stored in SQLite (zero-config) or PostgreSQL.

## Project Structure

```
access-nex/
├── main.go                     # Program entry point (starts the CLI)
├── go.mod / go.sum
├── internal/
│   ├── cli/
│   │   ├── cli.go              # Cobra command tree (user/app/provider/server)
│   │   ├── migrate.go          # `migrate` command: legacy JSON → SQL import
│   │   ├── keys.go             # Signing-key loading + rotate/list/retire commands
│   │   ├── admin.go            # user promote/demote, audit log viewer
│   │   └── groups.go           # group create/list/delete/add-member/remove-member
│   ├── database/
│   │   ├── database.go         # Opens SQLite or PostgreSQL, dialect-aware placeholder rebinding
│   │   └── schema.go           # CREATE TABLE script + column migrations (both backends)
│   ├── store/                  # SQL CRUD layer
│   │   ├── store.go            #   shared helpers
│   │   ├── users.go            #   users table, lockout, password/TOTP, account linking
│   │   ├── apps.go             #   applications table
│   │   ├── providers.go        #   providers table (internal + external)
│   │   ├── runtime.go          #   auth codes, tokens, sessions
│   │   ├── grants.go           #   consent grants
│   │   ├── keys.go             #   signing_keys table
│   │   ├── identities.go       #   linked external identities
│   │   ├── groups.go           #   groups / group_members
│   │   ├── device.go           #   device_codes table (RFC 8628)
│   │   └── audit.go            #   audit_log table
│   ├── server/                 # HTTP OIDC/OAuth2 provider
│   │   ├── server.go           #   routes, sessions, lockout, per-client CORS
│   │   ├── oidc.go             #   /authorize /token /userinfo /introspect /revoke /register ...
│   │   ├── proxy.go            #   external-provider SSO proxy (/oauth/start, /oauth/callback)
│   │   ├── web.go              #   dashboard, login form, consent screen, portal
│   │   ├── totp_ui.go          #   2FA enrollment (QR) + login challenge pages
│   │   ├── portal_self.go      #   self-service: password, grants, sessions, identities
│   │   ├── device.go           #   RFC 8628 device authorization grant
│   │   ├── tokenexchange.go    #   RFC 8693 token exchange
│   │   ├── dpop.go             #   RFC 9449 DPoP proof validation + JWK thumbprint
│   │   ├── logout.go           #   back-channel + front-channel logout notification
│   │   ├── admin.go            #   /admin UI + /api/admin/* JSON API
│   │   ├── ratelimit.go        #   per-IP rate limiting
│   │   ├── jwe.go              #   ID-token encryption (RSA-OAEP-256 + A256GCM)
│   │   └── helpers.go          #   JSON/PKCE/scope utilities
│   ├── models/models.go        # Shared types + built-in provider templates
│   └── secrets/                # AES-GCM encryption, RSA key gen, TOTP, self-signed TLS certs
└── .access-nex/                # Local runtime data (gitignored) — always used for the AES
                                 # box key and legacy signing key, regardless of DB backend
    ├── access-nex.db           #   SQLite database (unless --db points at PostgreSQL)
    ├── secret.key              #   AES key encrypting provider client secrets + signing keys
    └── signing.pem             #   legacy RSA signing key (imported into signing_keys on first run)
```

## Database

Two backends, selected by `--db`:

- **SQLite (default)** — a file inside `--config` (default `.access-nex/`), pure Go (`modernc.org/sqlite`), no C compiler needed. Zero configuration.
- **PostgreSQL** — pass `--db postgres://user:pass@host/dbname?sslmode=disable`. Useful for multi-instance deployments (SQLite allows only one writer process). The store layer writes ordinary `?`-placeholder SQL; [internal/database/database.go](internal/database/database.go) rebinds it to `$1, $2, ...` and adapts a couple of driver differences (e.g. boolean encoding) transparently — no query text differs between backends.

Either way, `--config DIR` still selects where the AES box key and legacy signing key files live.

| Table            | Contents |
|------------------|----------|
| `users`          | Local accounts (bcrypt hashes, optional TOTP secret, lockout state, admin flag) and accounts provisioned from external providers |
| `providers`      | One `internal` row for the local issuer, plus external OAuth2/OIDC providers with encrypted client secrets |
| `applications`   | Registered OAuth2/OIDC clients: redirect URIs, scopes, ID-token encryption key, logout URIs |
| `auth_codes`     | Single-use authorization codes |
| `access_tokens`  | Issued access tokens (introspection, revocation, DPoP thumbprint) |
| `refresh_tokens` | Single-use refresh tokens with rotation families (replay revokes the family) |
| `sessions`       | Browser login sessions |
| `grants`         | Remembered consent decisions per user + application |
| `signing_keys`   | JWT signing keys (encrypted); one active, older keys stay in JWKS |
| `identities`     | External identities linked to local users (account linking) |
| `device_codes`   | RFC 8628 device authorization flow state |
| `groups` / `group_members` | Roles/teams, exposed as the `groups` claim |
| `audit_log`      | Security events: logins, consent, token issuance, admin actions, key rotation |

Because runtime state is persisted, logins and issued tokens survive server restarts. Expired rows are purged every 10 minutes while the server runs.

### Migrating from the JSON version

```bash
./access-nex migrate
```

Imports the pre-SQL `users.json` / `apps.json` / `providers.json` files if present in `--config`. Plaintext passwords become bcrypt hashes; provider secrets are re-encrypted with AES-GCM. Safe to re-run — existing rows are skipped.

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
| `user add/list/delete` | Manage local users (bcrypt hashes; `--admin` grants admin rights) |
| `user promote/demote` | Grant or revoke admin rights (access to `/admin`) |
| `app create/list/show/update/delete` | Manage OAuth2/OIDC client applications |
| `app update --id-token-enc-key key.pem` | Encrypt ID tokens (JWE) for this client |
| `app update --backchannel-logout-uri / --frontchannel-logout-uri` | Register logout notification endpoints |
| `provider self init/info` | Initialize/inspect the local OIDC provider |
| `provider self rotate-key/list-keys/retire-key` | JWT signing-key rotation with kid rollover |
| `provider add/list/show/update/delete` | Manage external providers (`-t google\|github\|microsoft\|discord\|okta\|custom`) |
| `group create/list/delete` | Manage groups/roles |
| `group add-member/remove-member` | Manage group membership |
| `audit -n 50` | Show recent audit log entries |
| `migrate` | Import legacy JSON data into SQL |
| `server --addr :8080` | Run the HTTP provider |
| `server --tls-cert/--tls-key` | Serve HTTPS with your own certificate |
| `server --tls-self-signed` | Serve HTTPS with an in-memory self-signed cert (dev/local) |

Global flags: `--config DIR` (default `.access-nex`, holds the AES/signing keys and the SQLite file), `--db DSN` (use PostgreSQL instead of SQLite).

## Server Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET/POST /authorize` | Authorization endpoint (login, 2FA, consent, code issuance, PKCE) |
| `POST /token` | `authorization_code`, `refresh_token`, `client_credentials`, device code, token exchange |
| `GET /userinfo` | Claims for a bearer (or DPoP-bound) access token |
| `GET /jwks` | Public signing keys (all non-retired) |
| `POST /introspect`, `/revoke` | RFC 7662 / 7009 |
| `POST /register` | RFC 7591 dynamic client registration (persisted to SQL) |
| `POST /device_authorize`, `GET/POST /device` | RFC 8628 device authorization grant |
| `GET /oauth/providers`, `/oauth/start`, `/oauth/callback` | External-provider SSO proxy |
| `GET /`, `/login`, `/portal`, `/apps` | Web UI |
| `GET /admin`, `/api/admin/*` | Admin console + JSON API (requires an admin user) |

### Consent

After login, users see a consent screen ("App X wants access to: profile, email…"). Approvals are stored in the `grants` table and skipped on later logins. `prompt=consent` forces the screen again; `prompt=login`/`select_account` force re-authentication; `prompt=none` fails with `login_required`/`consent_required` when interaction would be needed. `response_mode=form_post` is supported.

### Two-factor authentication (TOTP)

From the portal (`/portal/2fa`), a user can enable TOTP: a QR code (RFC 6238, compatible with Google Authenticator, Authy, 1Password, etc.) is shown alongside the raw secret, and a confirmation code is required before it activates. Once enabled, both `/login` and `/authorize` insert a second "enter your code" step after the password, backed by a short-lived server-side pending-login token (no third-party TOTP library — implemented directly against stdlib crypto in [internal/secrets/totp.go](internal/secrets/totp.go)).

### Portal self-service

Signed-in users manage their own account at `/portal`:
- **Security** — change password, enable/disable 2FA
- **Authorized Applications** — see and revoke consent grants
- **Active Sessions** — see and end sessions on other devices (current device is flagged)
- **Linked Accounts** — see and unlink external identities (blocked if it's the only sign-in method and no password is set, to prevent lockout)

### Account linking

When an external provider reports a **verified** email (`email_verified: true`) that matches exactly one local user, the external identity is linked to that user instead of creating a duplicate account.

### Logout notification (back-channel / front-channel)

When a session ends (`/end_session` or `/portal/logout`), every application the user authorized (per `grants`) that registered a logout URI is notified:
- **Back-channel** — a signed OIDC logout token is POSTed server-to-server (fire-and-forget, doesn't block the user's own logout).
- **Front-channel** — the logout confirmation page loads each app's front-channel URI in a hidden iframe, running in the user's own browser session with that app.

Register with `access-nex app update --id CLIENT_ID --backchannel-logout-uri ... --frontchannel-logout-uri ...`.

### Device authorization grant (RFC 8628)

For CLIs, TVs, and other input-constrained clients: `POST /device_authorize` returns a `user_code` ("XXXX-XXXX") and `verification_uri`; the user enters the code at `/device` (or opens `verification_uri_complete`) on any browser, signs in, and approves. The device polls `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` until it receives tokens (or `authorization_pending`/`slow_down`/`access_denied`/`expired_token`).

### Token exchange (RFC 8693)

A confidential client can trade a token it holds for a new one scoped to a different audience — service-to-service delegation without re-running the login flow:

```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<existing access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<target client_id>
```

The subject is preserved; scope can only be narrowed, never widened. The issued token carries an `act` claim recording which client performed the exchange.

### DPoP — sender-constrained tokens (RFC 9449)

A client that generates an EC (P-256) or RSA key pair and sends a signed `DPoP` proof header on `/token` gets back a token bound to that key (`cnf.jkt` claim, `token_type: DPoP`). Using it later (e.g. at `/userinfo`) requires the `Authorization: DPoP <token>` scheme plus a fresh matching proof — a stolen bearer token alone isn't enough. Implemented directly against stdlib crypto ([internal/server/dpop.go](internal/server/dpop.go)), no JOSE dependency.

### Groups claim

`access-nex group create/add-member` manages roles; a client requesting the `groups` scope gets a `groups: [...]` claim in the ID token and `/userinfo` response. Useful for e.g. Portainer's OAuth team auto-assignment, which reads a claim like this to place users into teams on login.

### Admin console

Give a user admin rights (`access-nex user promote -u alice` or `user add --admin`), sign in at `/login`, then open `/admin` to manage users, applications, and providers and to view the audit log in the browser.

### External provider flow

`/oauth/start?provider_id=X&client_id=Y&redirect_uri=Z` redirects the user to the external provider. After the user signs in, `/oauth/callback` exchanges the provider's code, fetches userinfo, creates (or links) a row in the `users` table, and redirects back to the app with a **local** authorization code that the app exchanges at `/token` like any other login.

## HTTPS

```bash
./access-nex server --tls-cert cert.pem --tls-key key.pem   # your own certificate
./access-nex server --tls-self-signed                       # in-memory self-signed cert (dev/local)
```

Set the issuer to `https://...` (`provider self init --issuer https://...`) when serving TLS — that's what flips cookies to `Secure` and is checked at server startup.

## Connecting Portainer (or any Dockerized client)

Portainer's OAuth settings make **two kinds** of requests:

- **Browser-side** (Authorization URL, Logout URL) — resolved on *your* machine, so `localhost:8080` works.
- **Server-side** (Access Token URL, Resource URL) — made from *inside the Portainer container*, where `localhost` is the container itself. Use `host.docker.internal` instead.

Working configuration for Portainer at `https://localhost:9443`:

| Portainer setting | Value |
|-------------------|-------|
| Provider | Custom |
| Client ID / Secret | from `access-nex app create` output |
| Authorization URL | `http://localhost:8080/authorize` |
| Access Token URL | `http://host.docker.internal:8080/token` |
| Resource URL | `http://host.docker.internal:8080/userinfo` |
| Redirect URL | `https://localhost:9443/` (must exactly match a registered redirect URI) |
| Logout URL | `http://localhost:8080/end_session` |
| User Identifier | `email` |
| Scopes | `openid profile email` (add `groups` for team auto-assignment) |
| Auth Style | In Params (client_secret_post) |

If authentication fails, check `docker logs portainer` — OAuth errors (connection refused, invalid client, redirect mismatch) are logged there.

## Security Notes

Suitable for development, internal tooling, and small deployments. Implemented: bcrypt password hashes with 5-attempt/15-minute lockout, optional TOTP 2FA, AES-256-GCM encryption of provider secrets and signing keys at rest, RS256 JWTs with key rotation, single-use auth codes and refresh tokens with reuse detection (family revocation), DPoP sender-constrained tokens, per-IP rate limiting on `/token` and logins, per-client CORS, Secure cookies over HTTPS, consent with remembered grants, back-channel/front-channel logout, and an audit log. Still open: email verification for local accounts, and DPoP nonce/replay protection is proof-freshness-window based rather than server-issued-nonce based (RFC 9449 §8 optional feature).
