# The frontend/backend split

Access-Nex is two services:

- **The Go backend** (`internal/server`) implements the OIDC/OAuth2 protocol,
  sessions, 2FA/WebAuthn, and everything else as a JSON API (`/api/v1/*` for
  account management, `/api/admin/*` for admin) plus the OAuth2/OIDC
  endpoints themselves. It renders no HTML at all.
- **The Python/FastAPI frontend** (`frontend/`, entry point `main.py` at the
  repo root) renders every browser-facing page — home, login, 2FA, consent,
  portal, admin console, device flow, password reset — using that JSON API,
  and transparently proxies anything else (the OAuth2/OIDC endpoints, form
  submissions its pages post to, ...) straight through to the Go backend.
  Point a browser at the frontend (`ACCESS_NEX_BACKEND_URL` tells it where
  the backend is), not at the Go backend directly — the backend has no pages
  of its own to serve.

Because the split runs through a JSON API rather than any Python-specific
hook, the frontend isn't privileged: it's just the first consumer of a
contract any other frontend, in any language, could implement the same way.
Replacing it doesn't require touching the Go code, and a replacement can run
side by side with it while you migrate.

The full HTTP contract is in [openapi.yaml](openapi.yaml). This document is
the "why" and "how" behind it.

## What's API-first vs. browser-only

| Concern | Endpoints | Shape |
|---|---|---|
| OAuth2/OIDC protocol | `/authorize`, `/token`, `/userinfo`, `/jwks`, `/introspect`, `/revoke`, `/register`, `/device_authorize` | JSON, except `/authorize` which is a browser-navigated redirect flow per spec — that's inherent to OAuth2, not a Go-specific limitation |
| Account management | `/api/v1/*` (login, 2FA, password, sessions, grants, linked identities, password reset) | JSON |
| Passkey/security-key ceremonies | `/portal/webauthn/*`, `/login/webauthn/*` | JSON (WebAuthn is a JS/browser API either way) |
| Admin (users/apps/providers/audit) | `/api/admin/*` | JSON |
| Frontend support data (`internal/server/page_support.go`) | Extra `/api/v1/*` routes — home-page counts, the public app directory, 2FA/device-flow status — that exist only because a rendered page needs them | JSON, not part of the stable contract in openapi.yaml |
| Metrics | `/metrics` | Prometheus text format |
| **HTML pages** (the frontend's job) | `/`, `/login`, `/login/2fa`, `/consent`, `/portal`, `/portal/2fa`, `/admin`, `/device`, `/apps`, `/forgot-password`, `/reset-password`, `/message`, `/logout` | Server-rendered HTML (Jinja2) |

A replacement frontend re-implements the HTML-page row and calls everything
else directly. Nothing in the Go server needs to change to support this — the
JSON endpoints are the same ones `frontend/` already calls.

## How `/authorize` hands off to the frontend

`/authorize` keeps 100% of its OAuth2 logic in Go (client/redirect_uri
validation, session/consent checks, code issuance) — nothing about the
protocol itself moved. The only change is what happens when it needs to
*show something* mid-flow: instead of rendering HTML inline, it 302-redirects
the browser to the frontend's `/login`, `/login/2fa`, or `/consent`, with the
original request's fields (client_id, redirect_uri, scope, state, nonce,
code_challenge, ...) carried as query parameters (`internal/server/web.go`'s
`redirectToOAuthLogin`/`redirectToOAuthTOTP`/`redirectToConsent`). Those
pages render a form whose `action` posts straight back to `/authorize` (or
`/login/2fa`, `/device`, ...) — which the frontend's catch-all proxy forwards
to Go unchanged, so the round trip is indistinguishable from same-origin.

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

`frontend/` *is* this topology, just with the reverse proxy built into the
frontend process itself instead of a separate nginx/Caddy/Traefik hop
(`frontend/backend.py`'s `proxy()`): every request lands on the frontend's
origin, which either renders a page or forwards the request to access-nex
verbatim (redirects, `Set-Cookie`, everything) — a browser never talks to
the Go backend directly. A from-scratch replacement frontend that isn't
built this way still needs *something* in front of both services doing the
same job.

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
