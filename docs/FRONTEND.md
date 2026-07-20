# Swapping the frontend

Access-Nex ships with a server-rendered HTML frontend (`/login`, `/portal`,
`/admin`, `/device`, the consent screen) written in Go, for zero-setup use.
That frontend is optional: everything it does is also reachable as JSON, so
it can be replaced with a custom frontend — in Python, or anything else —
without touching the Go code, and the two can run side by side while you
migrate.

The full HTTP contract is in [openapi.yaml](openapi.yaml). This document is
the "why" and "how" behind it.

## What's API-first vs. browser-only

| Concern | Endpoints | Shape |
|---|---|---|
| OAuth2/OIDC protocol | `/authorize`, `/token`, `/userinfo`, `/jwks`, `/introspect`, `/revoke`, `/register`, `/device_authorize` | JSON, except `/authorize` which is a browser-navigated redirect flow per spec — that's inherent to OAuth2, not a Go-specific limitation |
| Account management | `/api/v1/*` (login, 2FA, password, sessions, grants, linked identities, password reset) | JSON |
| Passkey/security-key ceremonies | `/portal/webauthn/*`, `/login/webauthn/*` | JSON (WebAuthn is a JS/browser API either way) |
| Admin (users/apps/providers/audit) | `/api/admin/*` | JSON |
| Metrics | `/metrics` | Prometheus text format |
| **HTML pages** (replaceable) | `/login`, `/portal`, `/admin`, `/device`, consent screen | Server-rendered HTML + inline JS |

A custom frontend re-implements the HTML-page row and calls everything else
directly. Nothing in the Go server needs to change to support this — the
JSON endpoints are the same ones the built-in pages already call internally.

## Recommended topology: same-origin via reverse proxy

```
Browser → reverse proxy (nginx/Caddy/Traefik) → /            → custom frontend
                                                → /api/v1/*   → access-nex
                                                → /api/admin/* → access-nex
                                                → /authorize, /token, ... → access-nex
```

Same-origin is the path of least resistance because access-nex's session
cookie (`oidc_sid`) is `SameSite=Lax` (and `Secure` once served over HTTPS —
see `provider self init --issuer https://...`). Same-origin means the
browser sends it automatically on every `fetch()` to the API paths, with no
CORS configuration needed at all.

## Alternative: a separately-hosted, cross-origin frontend

If the frontend runs on its own domain instead:

1. Start access-nex with `--frontend-origin https://your-frontend.example`
   (repeatable for multiple origins). This adds the origin to the CORS
   allow-list enforced in [internal/server/server.go](../internal/server/server.go)'s
   `allowedOrigin` — the same mechanism already used for registered OAuth
   client redirect-URI origins.
2. Serve access-nex over HTTPS. Cross-origin cookies require
   `SameSite=None; Secure`, but access-nex only ever sets `Lax`+`Secure` —
   deliberately, since `None` would weaken CSRF protection for every other
   consumer of the cookie. In practice this means a cross-origin frontend
   should call the API through **its own backend** (a thin proxy/BFF) rather
   than directly from browser JS, so the session cookie travels same-origin
   between the browser and that backend, which then calls access-nex
   server-to-server. This is standard SPA-with-BFF practice, not something
   specific to access-nex.
3. `/authorize` still needs a real browser top-level navigation (it's
   redirect-based per the OAuth spec) — link or `window.location` to it
   directly, same as any OAuth client would.

## Auth flow for a custom frontend

1. `POST /api/v1/login` with `{username, password}`.
   - `{"status": "signed_in"}` → cookie set, done.
   - `{"status": "2fa_required", "token": "...", "methods": ["totp","webauthn"]}`
     → prompt for whichever method(s) are listed.
2. TOTP: `POST /api/v1/login/totp` with `{token, code}`.
3. Security key: `POST /login/webauthn/begin` with `{token}` → get
   `PublicKeyCredentialRequestOptions` → call `navigator.credentials.get()`
   in the browser → `POST /login/webauthn/finish` with the result.
4. `GET /api/v1/me` for the signed-in profile.
5. `POST /api/v1/logout` to end the session.

Mutating `/api/v1` calls (`POST`/`DELETE`) require the header
`X-Access-Nex-Api: 1` in addition to the session cookie — this is
defense-in-depth against CSRF, matching the existing `/api/admin` pattern
(`X-Access-Nex-Admin: 1`). `GET` requests don't need it.

## Admin console

`/api/admin/*` is the same JSON API the built-in `/admin` page already uses
— nothing new to build there beyond wiring a UI to it. It requires a session
belonging to a user with `is_admin` set (`access-nex user promote -u alice`).

## What stays server-side no matter what

Signing keys, password hashes, TOTP secrets, WebAuthn credentials, and
provider client secrets never leave access-nex — the frontend only ever
sees session cookies and OAuth tokens, the same as with the built-in pages.
Replacing the frontend doesn't change the trust boundary.
