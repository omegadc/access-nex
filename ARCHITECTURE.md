# Access-Nex Architecture: Frontend ↔ Backend

How the two halves of the project are organized internally, and how they talk
to each other. The one-sentence version: **the Python/FastAPI frontend is the
only thing browsers ever talk to; it renders every page itself and transparently
proxies everything else (OIDC protocol, JSON APIs, form posts) to the Go
backend over a private network.**

```
                        Browser
                           │  (single origin, e.g. http://localhost:8080)
                           ▼
        ┌──────────────────────────────────────┐
        │   frontend/  (Python · FastAPI)      │
        │   pages: /, /login, /portal, /admin… │
        │   static: /static/*                  │
        └──────────────┬───────────────────────┘
                       │ everything that isn't a page or /static
                       │ (catch-all reverse proxy, cookies forwarded)
                       ▼
        ┌──────────────────────────────────────┐
        │   Go backend  (main.go + internal/)  │
        │   /authorize /token /userinfo …      │
        │   /api/v1/*  /api/admin/*  /oauth/*  │
        └──────────────┬───────────────────────┘
                       ▼
              SQLite or PostgreSQL
```

---

## Backend (Go) — `main.go` + `internal/`

`main.go` is a two-line entry point that calls `internal/cli`. Everything else
lives under `internal/`, layered so that HTTP code never writes SQL and SQL
code never sees HTTP:

```
main.go ─▶ internal/cli ─▶ internal/server ─▶ internal/store ─▶ internal/database
                │                │                                     │
                │                ├─▶ internal/email    (SMTP / outbox.log)
                │                ├─▶ internal/secrets  (AES box, RSA keys, TOTP)
                │                └─▶ internal/models   (shared structs)
                └─▶ same store/secrets/email for CLI commands
```

### `internal/cli/` — command-line interface & process startup
| File | Role |
|---|---|
| `cli.go` | Cobra root: global flags (`--config`, `--db`, `--smtp-*`), `user`/`app`/`provider`/`server` commands. Builds the store, mailer, and server config, then starts the HTTP server. |
| `admin.go`, `groups.go` | `audit` and `group` subcommands. |
| `keys.go` | Loads/rotates the RSA signing keys (persisted via the store, encrypted by `secrets.Box`). |
| `migrate.go` | Legacy JSON-file → SQL migration (bcrypts old plaintext passwords). |
| `logging.go` | slog setup. |

### `internal/server/` — the HTTP OIDC/OAuth2 provider
| File | Role |
|---|---|
| `server.go` | `Server` struct, route table (`Handler()`), sessions, login rate limiting. |
| `oidc.go` | The protocol core: `/authorize`, `/token`, `/userinfo`, `/revoke`, `/introspect`, discovery, JWT signing (RS256). |
| `proxy.go` | External-provider SSO (`/oauth/start`, `/oauth/callback`): lets Google/Microsoft/GitHub log users into local apps. |
| `apiv1.go` | `/api/v1/*` JSON API — login, me, grants, sessions, TOTP, password change. **This is what the frontend's pages call.** |
| `admin.go` | `/api/admin/*` JSON API — users/apps/providers CRUD for the admin page. |
| `device.go`, `dpop.go`, `tokenexchange.go`, `webauthn.go`, `totp_ui.go` | Device flow (RFC 8628), DPoP (RFC 9449), token exchange (RFC 8693), WebAuthn, TOTP 2FA. |
| `reset.go`, `logout.go`, `jwe.go`, `metrics.go`, `ratelimit.go`, `helpers.go`, `page_support.go`, `portal_self.go`, `web.go` | Password reset, end-session + back/front-channel logout, ID-token encryption, Prometheus-style metrics, shared helpers. |

### `internal/store/` — all SQL lives here
One file per concern (`users.go`, `apps.go`, `providers.go`, `grants.go`,
`runtime.go` for codes/tokens, `identities.go` for account linking, plus
`audit.go`, `device.go`, `groups.go`, `keys.go`, `reset.go`, `webauthn.go`).
Only this package writes queries; everything uses `?` placeholders.

### `internal/database/` — backend-agnostic DB handle
`database.go` opens SQLite (zero-config default) or PostgreSQL (DSN starts
with `postgres://`) and transparently rebinds `?` → `$N` for Postgres.
`schema.go` holds the schema + column migrations.

### `internal/models/`, `internal/email/`, `internal/secrets/`
Shared structs (User, App, Provider, AuthCode, TokenRecord…) and the
provider templates (Google/Microsoft/GitHub/Discord/Okta URLs); the mailer
(real SMTP or dev `outbox.log`); crypto (AES-256-GCM secret box, RSA signing
keys, TOTP, self-signed TLS).

---

## Frontend (Python) — `frontend/`

Three small modules plus assets. FastAPI renders pages; it holds **no state
and no business logic** — every fact on every page comes from a backend API
call, and every form submission passes straight through to the backend.

| File | Role |
|---|---|
| `app.py` | All page routes (`/`, `/login`, `/login/2fa`, `/consent`, `/portal`, `/portal/2fa`, `/admin`, `/device`, `/apps`, `/forgot-password`, `/reset-password`, `/logout`, `/message`), the `/static` mount, and — registered **last** — the catch-all route that hands any unmatched path to `backend.proxy`. |
| `backend.py` | The bridge to Go: `proxy()` (byte-for-byte reverse proxy, preserves multiple `Set-Cookie` headers, strips hop-by-hop headers), `api()`/`get_json()` (server-side JSON fetches with the browser's cookie forwarded), `current_user()` (`GET /api/v1/me`). Each request gets its own httpx client over a shared connection pool so one user's cookies can never leak into another's proxied request. |
| `config.py` | Env-driven settings: `ACCESS_NEX_BACKEND_URL`, `ACCESS_NEX_BACKEND_TIMEOUT`, `ACCESS_NEX_BRAND`. |
| `templates/` | Jinja2 pages. `base_app.html` (signed-in chrome) and `base_auth.html` (login-style card) are the two layouts; the rest extend them. |
| `static/js/` | `portal.js` (app config viewer + OAuth flow test), `admin.js` (admin CRUD against `/api/admin/*`), `webauthn.js` (passkey ceremonies). |
| `Dockerfile` | Uvicorn image for the compose `frontend` service. |

### How a page renders (server-side path)

```
GET /portal
  → app.py: portal_page()
  → backend.py: current_user() ──▶ GET {backend}/api/v1/me        (cookie forwarded)
  → backend.py: get_json()     ──▶ GET {backend}/api/v1/grants, /sessions,
                                    /identities, /stats/active, /apps/configs, /totp
  → templates/portal.html rendered with that data
```

### How everything else flows (proxy path)

```
POST /api/v1/login   (or /token, /authorize, /api/admin/*, form posts…)
  → no page route matches
  → app.py: backend_proxy()  (catch-all, registered last)
  → backend.py: proxy()  ──▶ same method/path/body/headers to {backend}
  ← response relayed verbatim — including Set-Cookie (the Go session
    cookie) and redirects, which the browser then follows back through
    the frontend again
```

Because the browser only ever sees the frontend's origin, the Go session
cookie set through the proxy is **same-origin** — no CORS, no
`host.docker.internal`, no cookie-domain juggling.

---

## Deployment topology (`docker-compose.yml`)

```
                    host port 8080
                          │
   ┌──────────┐    ┌─────────────┐     ┌──────────────┐
   │ Browser  │───▶│  frontend   │────▶│  access-nex  │───▶ db (postgres:16)
   └──────────┘    │ (uvicorn,   │     │ (Go, :8080,  │     volume: accessnex-db
                   │  :8000)     │     │  no host     │
                   └─────────────┘     │  port)       │
                                       └──────────────┘
                                        volume: accessnex-config
                                        (AES key + signing keys)
```

- Only `frontend` publishes a host port (`8080:8000`) — it is the single
  origin browsers talk to.
- `ACCESS_NEX_BACKEND_URL=http://access-nex:8080` wires the frontend to the
  backend over the compose network.
- `--issuer http://localhost:8080` stays the *browser-visible* URL (the
  frontend's), because issued URLs and cookies must match what browsers
  actually reach; the frontend proxies those protocol paths through.
- The Go image is distroless — admin CLI runs via
  `docker compose exec access-nex access-nex --db "postgres://…" …`.

## Who owns which routes (single origin, split by path)

| Path | Served by |
|---|---|
| `/`, `/login`, `/portal`, `/admin`, `/device`, `/apps`, `/consent`, `/logout`, `/message`, `/forgot-password`, `/reset-password` | **Frontend** (Jinja2 templates) |
| `/static/*` | **Frontend** (static files) |
| `/authorize`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/end_session`, `/.well-known/*`, `/jwks` | **Backend** (via proxy) |
| `/api/v1/*` (session JSON API), `/api/admin/*` (admin JSON API) | **Backend** (via proxy) |
| `/oauth/providers`, `/oauth/start`, `/oauth/callback` (external SSO) | **Backend** (via proxy) |
| `/device/code`, `/device/token` (RFC 8628), `/metrics` | **Backend** (via proxy) |
