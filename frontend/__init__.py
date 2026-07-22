"""Python/FastAPI frontend for access-nex.

Renders every browser-facing HTML page (home, login, 2FA, consent, portal,
admin console, device flow, password reset, ...). It owns nothing else: all
business logic, sessions, and the OAuth2/OIDC protocol itself stay in the Go
backend (see internal/server). This package's job is to render templates and
transparently proxy everything it doesn't own to that backend, so a browser
only ever talks to one origin. See docs/FRONTEND.md for the full picture.
"""
