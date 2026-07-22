# Access-Nex: OIDC/OAuth2 Provider

A self-hosted OpenID Connect (OIDC) and OAuth 2.0 provider with a management CLI. Register applications, manage users, and federate sign-in through external identity providers (Google, Microsoft, GitHub, Discord, Okta, or any custom OAuth2/OIDC provider). Data is stored in SQLite (zero-config) or PostgreSQL.

The system is split into two services (see [docs/FRONTEND.md](docs/FRONTEND.md) for the full picture):

- **Go backend** (`internal/server`) — the OIDC/OAuth2 protocol itself, session/2FA/WebAuthn logic, and the JSON APIs (`/api/v1/*`, `/api/admin/*`). No HTML.
- **Python/FastAPI frontend** (`frontend/`) — every browser-facing page (home, login, 2FA, consent, portal, admin console, device flow, password reset). It renders templates using the backend's JSON APIs and transparently proxies everything else to the backend, so a browser only ever talks to one origin.

Ships as containers ([Dockerfile](Dockerfile) for the backend, [frontend/Dockerfile](frontend/Dockerfile) for the frontend, wired together in [docker-compose.yml](docker-compose.yml)).

## Project Structure

```
access-nex/
├── main.go                     # Go program entry point (starts the CLI)
├── main.py                     # Python frontend entry point (FastAPI app)
├── requirements.txt             # Python frontend dependencies
├── Dockerfile, docker-compose.yml, .dockerignore
├── frontend/                    # Python/FastAPI frontend — every browser-facing page
│   ├── app.py                   #   routes: render a page, or proxy to the Go backend
│   ├── backend.py               #   httpx client: JSON calls for page data + the raw proxy
│   ├── config.py                #   ACCESS_NEX_BACKEND_URL and friends (env vars)
│   ├── templates/                #   Jinja2 templates (one per page)
│   ├── static/css, static/js     #   stylesheet + WebAuthn/admin/portal client-side JS
│   └── Dockerfile
├── docs/
│   ├── openapi.yaml             # Full HTTP API contract
│   └── FRONTEND.md              # The backend/frontend split, and how to replace the frontend again
├── go.mod / go.sum
├── internal/
│   ├── cli/
│   │   ├── cli.go              # Cobra command tree (user/app/provider/server), SMTP + logging flags
│   │   ├── migrate.go          # `migrate` command: legacy JSON → SQL import
│   │   ├── keys.go             # Signing-key loading + rotate/list/retire commands
│   │   ├── admin.go            # user promote/demote, audit log viewer
│   │   ├── groups.go           # group create/list/delete/add-member/remove-member
│   │   └── logging.go          # --log-format/--log-level → log/slog logger
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
│   │   ├── reset.go            #   password_resets / email_verifications tables
│   │   ├── webauthn.go         #   webauthn_credentials table
│   │   └── audit.go            #   audit_log table
│   ├── server/                 # HTTP OIDC/OAuth2 provider
│   │   ├── server.go           #   routes, sessions, lockout, per-client + frontend CORS
│   │   ├── oidc.go             #   /authorize /token /userinfo /introspect /revoke /register ...
│   │   ├── proxy.go            #   external-provider SSO proxy (/oauth/start, /oauth/callback)
│   │   ├── web.go              #   direct login + logout: verify credentials, redirect to whichever frontend page comes next
│   │   ├── apiv1.go            #   /api/v1 JSON account API (for the frontend, or any custom one)
│   │   ├── page_support.go     #   /api/v1 data the frontend needs to render (stats, app directory, 2FA/device status) — not a stable contract
│   │   ├── totp_ui.go          #   2FA enrollment/disable mutations (rendering is the frontend's)
│   │   ├── webauthn.go         #   passkey/security-key registration + login (FIDO2)
│   │   ├── portal_self.go      #   self-service: password, grants, sessions, identities
│   │   ├── reset.go            #   forgot/reset password, email verification (mutations only)
│   │   ├── device.go           #   RFC 8628 device authorization grant
│   │   ├── tokenexchange.go    #   RFC 8693 token exchange
│   │   ├── dpop.go             #   RFC 9449 DPoP proof validation + server-issued nonce
│   │   ├── logout.go           #   back-channel logout notification + front-channel redirect
│   │   ├── admin.go            #   /api/admin/* JSON API (the /admin page itself is the frontend's)
│   │   ├── metrics.go          #   Prometheus /metrics
│   │   ├── ratelimit.go        #   per-IP rate limiting
│   │   ├── jwe.go              #   ID-token encryption (RSA-OAEP-256 + A256GCM)
│   │   └── helpers.go          #   JSON/PKCE/scope utilities
│   ├── models/models.go        # Shared types + built-in provider templates
│   ├── email/email.go          # SMTP mailer, with a file-logging fallback when unconfigured
│   └── secrets/                # AES-GCM encryption, RSA key gen, TOTP, self-signed TLS certs
└── .access-nex/                # Local runtime data (gitignored) — always used for the AES
                                 # box key and signing key, regardless of DB backend
    ├── access-nex.db           #   SQLite database (unless --db points at PostgreSQL)
    ├── secret.key              #   AES key encrypting provider client secrets + signing keys
    ├── signing.pem             #   legacy RSA signing key (imported into signing_keys on first run)
    └── outbox.log               #   emails written here when no --smtp-host is configured
```

## Database

Two backends, selected by `--db`:

- **SQLite (default)** — a file inside `--config` (default `.access-nex/`), pure Go (`modernc.org/sqlite`), no C compiler needed. Zero configuration.
- **PostgreSQL** — pass `--db postgres://user:pass@host/dbname?sslmode=disable`. Useful for multi-instance deployments (SQLite allows only one writer process) — it's also what [docker-compose.yml](docker-compose.yml) uses by default, since `docker exec` admin commands against a container's own SQLite file aren't reliably visible to the running server on every Docker volume backend, while PostgreSQL (a real client-server database) has no such issue. The store layer writes ordinary `?`-placeholder SQL; [internal/database/database.go](internal/database/database.go) rebinds it to `$1, $2, ...` and adapts a couple of driver differences (e.g. boolean encoding) transparently — no query text differs between backends.

Either way, `--config DIR` still selects where the AES box key and signing key files live.

| Table            | Contents |
|------------------|----------|
| `users`          | Local accounts (bcrypt hashes, optional TOTP secret, email verification, lockout state, admin flag) and accounts provisioned from external providers |
| `providers`      | One `internal` row for the local issuer, plus external OAuth2/OIDC providers with encrypted client secrets |
| `applications`   | Registered OAuth2/OIDC clients: redirect URIs, scopes, ID-token encryption key, logout URIs |
| `auth_codes`     | Single-use authorization codes |
| `access_tokens`  | Issued access tokens (introspection, revocation, DPoP thumbprint) |
| `refresh_tokens` | Single-use refresh tokens with rotation families (replay revokes the family) |
| `sessions`       | Browser login sessions |
| `grants`         | Remembered consent decisions per user + application |
| `signing_keys`   | JWT signing keys (encrypted); one active, older keys stay in JWKS |
| `identities`     | External identities linked to local users (account linking) |
| `webauthn_credentials` | Registered passkeys/security keys |
| `password_resets` / `email_verifications` | Single-use, expiring tokens for those flows |
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

# 1. Create a user
./access-nex user add -u alice -p secret123 -e alice@example.com -n "Alice Example"

# 2. Register an application
./access-nex app create -n "My App" -r http://localhost:9000/

# 3. (Optional) Add an external provider from a template
./access-nex provider add -n "Google SSO" -t google -c GOOGLE_CLIENT_ID -s GOOGLE_CLIENT_SECRET

# 4. Start the Go backend (auto-initializes the local provider on first run)
./access-nex server --addr :8080

# 5. In another terminal, start the Python frontend (this is what browsers talk to)
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Or with Docker: `docker compose up -d` (see [docker-compose.yml](docker-compose.yml) for first-time setup commands) — this starts both services and only publishes the frontend's port.

Open http://localhost:8000 (or `:8080` under Docker Compose, per that file's port mapping) for the dashboard, or `/login` to sign in and get ready-to-paste OAuth client configuration (e.g. for Portainer). Point a browser at the frontend, not directly at the Go backend's port — the backend has no pages of its own anymore.

## CLI Commands

| Command | Description |
|---------|-------------|
| `user add/list/delete` | Manage local users (bcrypt hashes; `--admin` grants admin rights, `--verified` marks the email pre-verified) |
| `user promote/demote` | Grant or revoke admin rights (access to `/admin`) |
| `app create/list/show/update/delete` | Manage OAuth2/OIDC client applications |
| `app update --id-token-enc-key key.pem` | Encrypt ID tokens (JWE) for this client |
| `app update --backchannel-logout-uri / --frontchannel-logout-uri` | Register logout notification endpoints |
| `provider self init/info` | Initialize/inspect the local OIDC provider (also happens automatically on first `server` start) |
| `provider self rotate-key/list-keys/retire-key` | JWT signing-key rotation with kid rollover |
| `provider add/list/show/update/delete` | Manage external providers (`-t google\|github\|microsoft\|discord\|okta\|custom`) |
| `group create/list/delete` | Manage groups/roles |
| `group add-member/remove-member` | Manage group membership |
| `audit -n 50` | Show recent audit log entries |
| `migrate` | Import legacy JSON data into SQL |
| `server --addr :8080` | Run the HTTP provider |
| `server --issuer URL` | Issuer to auto-initialize with, if not already set (default `http://localhost:8080`) |
| `server --tls-cert/--tls-key` | Serve HTTPS with your own certificate |
| `server --tls-self-signed` | Serve HTTPS with an in-memory self-signed cert (dev/local) |
| `server --dpop-require-nonce` | Require a server-issued nonce in DPoP proofs (RFC 9449 §8) |
| `server --frontend-origin URL` | Extra CORS origin(s) for a separately-hosted frontend (repeatable) |
| `server --log-format text\|json --log-level debug\|info\|warn\|error` | Structured logging |

Global flags: `--config DIR` (default `.access-nex`, holds the AES/signing keys and the SQLite file), `--db DSN` (use PostgreSQL instead of SQLite), `--smtp-host/--smtp-port/--smtp-username/--smtp-password/--smtp-from` (outgoing mail for password reset/verification; omit `--smtp-host` to write mail to `--config/outbox.log` instead of sending it — handy for local/dev use).

## Server Endpoints

The full contract, including request/response bodies, is in [docs/openapi.yaml](docs/openapi.yaml).

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET/POST /authorize` | Authorization endpoint (login, 2FA, consent, code issuance, PKCE) |
| `POST /token` | `authorization_code`, `refresh_token`, `client_credentials`, device code, token exchange |
| `GET /userinfo` | Claims for a bearer (or DPoP-bound) access token |
| `GET /jwks` | Public signing keys (all non-retired) |
| `POST /introspect`, `/revoke` | RFC 7662 / 7009 |
| `POST /register` | RFC 7591 dynamic client registration (persisted to SQL) |
| `POST /device_authorize`, `POST /device` | RFC 8628 device authorization grant (approve/deny; the entry/confirm page is the frontend's, backed by `GET /api/v1/device`) |
| `GET /oauth/providers`, `/oauth/start`, `/oauth/callback` | External-provider SSO proxy |
| `/api/v1/*` | JSON account API (login, 2FA, password, sessions, grants, identities) for the frontend, or any custom one |
| `POST /portal/webauthn/*`, `/login/webauthn/*` | Passkey/security-key registration and login (JSON) |
| `/api/admin/*` | Admin JSON API (requires an admin user; the `/admin` console itself is the frontend's) |
| `GET /metrics` | Prometheus metrics |

Everything above is served by the Go backend directly. Every browser-facing page (`/`, `/login`, `/login/2fa`, `/consent`, `/portal`, `/portal/2fa`, `/admin`, `/device`, `/apps`, `/forgot-password`, `/reset-password`, `/message`, `/logout`) is served by the Python frontend, which renders templates from the JSON API above and transparently proxies everything else to the backend.

### Consent

After login, users see a consent screen ("App X wants access to: profile, email…"). Approvals are stored in the `grants` table and skipped on later logins. `prompt=consent` forces the screen again; `prompt=login`/`select_account` force re-authentication; `prompt=none` fails with `login_required`/`consent_required` when interaction would be needed. `response_mode=form_post` is supported.

### Two-factor authentication: TOTP and passkeys

From the portal (`/portal/2fa`), a user can enable **TOTP** (a QR code, RFC 6238, compatible with Google Authenticator/Authy/1Password — implemented directly against stdlib crypto, no third-party TOTP library) and/or register **passkeys/security keys** (FIDO2/WebAuthn — YubiKeys, Windows Hello, Touch ID; delegated to `github.com/go-webauthn/webauthn` since the CBOR/COSE/attestation parsing genuinely warrants a well-audited dependency). Both `/login` and `/authorize` insert a second step after the password when either is enrolled, offering whichever method(s) are available; a security-key login is verified with the same challenge/response flow a browser drives via `navigator.credentials.get()`.

### Portal self-service

Signed-in users manage their own account at `/portal`:
- **Security** — change password, enable/disable 2FA (TOTP + passkeys), resend the email verification link
- **Authorized Applications** — see and revoke consent grants
- **Active Sessions** — see and end sessions on other devices (current device is flagged)
- **Linked Accounts** — see and unlink external identities (blocked if it's the only sign-in method and no password is set, to prevent lockout)

### Password reset & email verification

`/forgot-password` emails a single-use, 1-hour reset link (the response is identical whether or not the address matched an account, to avoid leaking who has one). New local accounts start unverified unless created with `--verified`; `/portal` shows a banner with a resend button, and `/verify-email?token=...` confirms it. Without `--smtp-host` configured, mail is written to `--config/outbox.log` instead of sent — the whole flow works end-to-end without any mail server for local/dev use.

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

A client that generates an EC (P-256) or RSA key pair and sends a signed `DPoP` proof header on `/token` gets back a token bound to that key (`cnf.jkt` claim, `token_type: DPoP`). Using it later (e.g. at `/userinfo`) requires the `Authorization: DPoP <token>` scheme plus a fresh matching proof — a stolen bearer token alone isn't enough. With `server --dpop-require-nonce`, the server also demands a server-issued nonce in each proof (RFC 9449 §8): the first proof without one is rejected with `use_dpop_nonce` and a `DPoP-Nonce` response header, the client retries with it, and every subsequent response proactively carries the next nonce so a well-behaved client only pays that round trip once. Implemented directly against stdlib crypto ([internal/server/dpop.go](internal/server/dpop.go)), no JOSE dependency.

### Groups claim

`access-nex group create/add-member` manages roles; a client requesting the `groups` scope gets a `groups: [...]` claim in the ID token and `/userinfo` response. Useful for e.g. Portainer's OAuth team auto-assignment, which reads a claim like this to place users into teams on login.

### Admin console

Give a user admin rights (`access-nex user promote -u alice` or `user add --admin`), sign in at `/login`, then open `/admin` to manage users, applications, and providers and to view the audit log in the browser. The page itself is rendered by the Python frontend; it drives the Go backend's `/api/admin/*` JSON API directly from the browser.

### External provider flow

`/oauth/start?provider_id=X&client_id=Y&redirect_uri=Z` redirects the user to the external provider. After the user signs in, `/oauth/callback` exchanges the provider's code, fetches userinfo, creates (or links) a row in the `users` table, and redirects back to the app with a **local** authorization code that the app exchanges at `/token` like any other login.

## Swapping the frontend

The Python/FastAPI frontend in `frontend/` isn't special-cased by the Go backend — it's just the first consumer of a fully JSON-first API surface. Every page it renders (`/login`, `/portal`, `/admin`, `/device`, ...) is backed entirely by `/api/v1` (account management), `/api/admin` (admin), and the WebAuthn endpoints, so it can be replaced with a different frontend, in any language, without touching the Go server at all. See [docs/FRONTEND.md](docs/FRONTEND.md) for the recommended topology (same-origin via reverse proxy — which is exactly what `frontend/` does for the shipped frontend — or a cross-origin SPA with `--frontend-origin`) and [docs/openapi.yaml](docs/openapi.yaml) for the full contract.

## Observability

- **Structured logs**: `server --log-format json --log-level info` (stdlib `log/slog`).
- **Metrics**: `GET /metrics` (Prometheus text format) — HTTP request counts/latency by route, login outcomes, tokens issued by grant type, DPoP rejections. Unauthenticated by design (standard Prometheus practice); keep it off the public internet at the network/reverse-proxy layer.
- **Audit log**: `access-nex audit` or `/api/admin/audit` — logins, consent, token issuance, admin actions, key rotation, and more, persisted in SQL.

## Docker

```bash
docker compose up -d
docker compose exec access-nex access-nex --db "$ACCESS_NEX_DB" user add -u admin -p CHANGE_ME --admin --verified
docker compose exec access-nex access-nex --db "$ACCESS_NEX_DB" app create -n "My App" -r https://your-app/callback
```

[docker-compose.yml](docker-compose.yml) runs three services: PostgreSQL, the Go backend (`access-nex`, see [Database](#database) for why Postgres, not SQLite, is the compose default), and the Python frontend (`frontend`). Only `frontend` publishes a host port (`8080:8000`) — it's the single origin browsers and OAuth clients reach; `access-nex` itself isn't published, only reachable at `http://access-nex:8080` inside the compose network (which is also how `frontend` reaches it, via `ACCESS_NEX_BACKEND_URL`).

The backend image is a multi-stage build ([Dockerfile](Dockerfile)) producing a fully static binary (`CGO_ENABLED=0`, pure-Go SQLite/Postgres drivers) on `gcr.io/distroless/static-debian12:nonroot` — no shell, no package manager, runs as a non-root user. The local provider auto-initializes on first `server` start, so no separate init step is needed in a container that has no shell to script one with. The frontend image ([frontend/Dockerfile](frontend/Dockerfile)) is a plain `python:3.12-slim` running `uvicorn`.

On the same Docker network, other containers (Portainer, your app) reach access-nex at `http://access-nex:8080` directly — no `host.docker.internal` workaround needed there, unlike when access-nex runs as a bare process on the host (see below).

## Connecting Portainer (or any Dockerized client)

Portainer's OAuth settings make **two kinds** of requests:

- **Browser-side** (Authorization URL, Logout URL) — resolved on *your* machine, so wherever the frontend is published (`localhost:8080` under `docker-compose.yml`, or `localhost:8000` if you ran `uvicorn` directly per the Quick Start) works. These get proxied straight through to the backend, so the URL is the same as if the backend were public.
- **Server-side** (Access Token URL, Resource URL) — made from *inside the Portainer container*, where `localhost` is the container itself. Use `host.docker.internal` instead (or, if both are Docker containers on the same compose network, the access-nex service name — see [Docker](#docker) above), pointed at whichever service Portainer can actually reach: the Go backend directly if it's on that network, or the frontend if not.

Working configuration for Portainer at `https://localhost:9443`, with access-nex reachable via `docker-compose.yml` (frontend published at `:8080`):

| Portainer setting | Value |
|-------------------|-------|
| Provider | Custom |
| Client ID / Secret | from `access-nex app create` output |
| Authorization URL | `http://localhost:8080/authorize` |
| Access Token URL | `http://access-nex:8080/token` (same compose network) or `http://host.docker.internal:8080/token` (backend published directly on the host) |
| Resource URL | `http://access-nex:8080/userinfo` or `http://host.docker.internal:8080/userinfo` |
| Redirect URL | `https://localhost:9443/` (must exactly match a registered redirect URI) |
| Logout URL | `http://localhost:8080/end_session` |
| User Identifier | `email` |
| Scopes | `openid profile email` (add `groups` for team auto-assignment) |
| Auth Style | In Params (client_secret_post) |

If authentication fails, check `docker logs portainer` — OAuth errors (connection refused, invalid client, redirect mismatch) are logged there.

## Security Notes

Suitable for development, internal tooling, and small deployments. Implemented: bcrypt password hashes with 5-attempt/15-minute lockout, TOTP 2FA and FIDO2/WebAuthn passkeys, AES-256-GCM encryption of provider secrets and signing keys at rest, RS256 JWTs with key rotation, single-use auth codes and refresh tokens with reuse detection (family revocation), DPoP sender-constrained tokens with optional server-issued nonces, per-IP rate limiting on `/token` and logins, per-client CORS, Secure cookies over HTTPS, consent with remembered grants, back-channel/front-channel logout, password reset and email verification, and a full audit log.
