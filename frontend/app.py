"""The FastAPI application: every browser-facing page, plus a catch-all that
transparently proxies anything else (the OIDC/OAuth2 protocol endpoints,
/api/v1/*, /api/admin/*, form submissions the pages below post to, ...) to
the Go backend. See docs/FRONTEND.md for the split this implements.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse

from .backend import current_user, get_json, proxy
from .config import settings

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# The OAuth2/OIDC "authorization request" fields that round-trip through the
# login/2FA/consent pages as hidden form fields — mirrors authRequest in
# internal/server/oidc.go.
AUTH_FIELDS = [
    "response_type", "response_mode", "client_id", "redirect_uri", "scope",
    "state", "nonce", "code_challenge", "code_challenge_method", "prompt",
]

SCOPE_DESCRIPTIONS = {
    "openid": "Confirm your identity (OpenID Connect sign-in)",
    "profile": "View your name and username",
    "email": "View your email address",
    "offline_access": "Stay signed in (refresh tokens)",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Shared connection pool only — no shared cookie jar. See
    # backend._scoped_client for why each request gets its own httpx client
    # (built on this same transport) rather than a single shared client.
    app.state.http_transport = httpx.AsyncHTTPTransport()
    try:
        yield
    finally:
        await app.state.http_transport.aclose()


app = FastAPI(title=settings.brand, lifespan=lifespan)


def ctx(request: Request, title: str, **extra) -> dict:
    """Template context every page shares (request, brand, title), plus
    whatever page-specific data the caller adds."""
    data = {"request": request, "brand": settings.brand, "title": title}
    data.update(extra)
    return data


def auth_fields(query) -> dict:
    return {k: query.get(k, "") for k in AUTH_FIELDS}


def encode_fields(fields: dict) -> str:
    return urlencode({k: v for k, v in fields.items() if v})


def full_path(request: Request) -> str:
    path = request.url.path
    if request.url.query:
        path += "?" + request.url.query
    return path


# ── Home ─────────────────────────────────────────────────────────────────────


@app.get("/")
async def home(request: Request):
    user = await current_user(request)
    _, stats = await get_json(request, "/api/v1/stats")
    return templates.TemplateResponse(
        request,
        "home.html", ctx(request, "Home", user=user, stats=stats or {})
    )


# ── Direct login + OAuth-flow login (dual-mode: client_id present = OAuth) ──


@app.get("/login")
async def login_page(request: Request):
    q = request.query_params
    error = q.get("error", "")
    if q.get("client_id"):
        return templates.TemplateResponse(
            request,
            "login.html",
            ctx(
                request, "Sign In", mode="oauth", fields=auth_fields(q),
                client_name=q.get("client_name", ""), error=error,
            ),
        )
    return_to = q.get("return_to") or "/portal"
    if await current_user(request):
        return RedirectResponse(return_to, status_code=302)
    return templates.TemplateResponse(
        request,
        "login.html",
        ctx(request, "Sign In", mode="direct", return_to=return_to, error=error),
    )


@app.get("/login/2fa")
async def login_2fa_page(request: Request):
    q = request.query_params
    token = q.get("token", "")
    error = q.get("error", "")
    if q.get("client_id"):
        fields = auth_fields(q)
        return templates.TemplateResponse(
            request,
            "login_2fa.html",
            ctx(
                request, "Two-Factor", mode="oauth", fields=fields, token=token,
                client_name=q.get("client_name", ""), error=error,
                qs=encode_fields(fields),
            ),
        )
    return_to = q.get("return_to") or "/portal"
    return templates.TemplateResponse(
        request,
        "login_2fa.html",
        ctx(
            request, "Two-Factor", mode="direct", token=token,
            return_to=return_to, return_to_json=json.dumps(return_to), error=error,
        ),
    )


@app.get("/consent")
async def consent_page(request: Request):
    q = request.query_params
    user = await current_user(request)
    if not user:
        return RedirectResponse("/login?" + urlencode(dict(q)), status_code=302)
    scope = q.get("scope", "")
    return templates.TemplateResponse(
        request,
        "consent.html",
        ctx(
            request, "Authorize", fields=auth_fields(q),
            client_name=q.get("client_name", ""),
            scopes=scope.split() if scope else [],
            scope_descriptions=SCOPE_DESCRIPTIONS,
            username=user.get("username", ""),
        ),
    )


# ── Portal ───────────────────────────────────────────────────────────────────


@app.get("/portal")
async def portal_page(request: Request):
    user = await current_user(request)
    if not user:
        return RedirectResponse("/login?return_to=/portal", status_code=302)
    _, grants = await get_json(request, "/api/v1/grants")
    _, sessions = await get_json(request, "/api/v1/sessions")
    _, identities = await get_json(request, "/api/v1/identities")
    _, active_stats = await get_json(request, "/api/v1/stats/active")
    _, app_configs = await get_json(request, "/api/v1/apps/configs")
    _, totp = await get_json(request, "/api/v1/totp")
    q = request.query_params
    return templates.TemplateResponse(
        request,
        "portal.html",
        ctx(
            request, "Portal", user=user,
            grants=(grants or {}).get("grants", []),
            sessions=(sessions or {}).get("sessions", []),
            identities=(identities or {}).get("identities", []),
            active_stats=active_stats or {},
            app_configs=(app_configs or {}).get("apps", []),
            issuer=(app_configs or {}).get("issuer", ""),
            totp=totp or {},
            ok=q.get("ok", ""), error=q.get("error", ""),
        ),
    )


@app.get("/portal/2fa")
async def portal_2fa_page(request: Request):
    user = await current_user(request)
    if not user:
        return RedirectResponse("/login?return_to=/portal/2fa", status_code=302)
    _, totp = await get_json(request, "/api/v1/totp")
    return templates.TemplateResponse(
        request,
        "portal_2fa.html",
        ctx(
            request, "Two-Factor", user=user, totp=totp or {},
            error=request.query_params.get("error", ""),
        ),
    )


# ── Admin ────────────────────────────────────────────────────────────────────


@app.get("/admin")
async def admin_page(request: Request):
    user = await current_user(request)
    if not user or not user.get("is_admin"):
        return RedirectResponse("/login?return_to=/admin", status_code=302)
    return templates.TemplateResponse(request, "admin.html", ctx(request, "Admin", user=user))


# ── Device flow ──────────────────────────────────────────────────────────────


@app.get("/device")
async def device_page(request: Request):
    user = await current_user(request)
    if not user:
        return RedirectResponse(
            "/login?" + urlencode({"return_to": full_path(request)}), status_code=302
        )
    q = request.query_params
    user_code = q.get("user_code", "").strip().upper()
    error = q.get("error", "")
    if user_code:
        status, data = await get_json(
            request, "/api/v1/device", params={"user_code": user_code}
        )
        if status == 200:
            return templates.TemplateResponse(
                request,
                "device.html",
                ctx(
                    request, "Device Sign-In", mode="confirm",
                    user_code=data["user_code"], client_name=data["client_name"],
                    scopes=data.get("scopes") or [], scope_descriptions=SCOPE_DESCRIPTIONS,
                ),
            )
        error = error or "That code is invalid or has expired."
    return templates.TemplateResponse(
        request,
        "device.html",
        ctx(request, "Device Sign-In", mode="entry", prefill=user_code, error=error),
    )


@app.get("/device/result")
async def device_result_page(request: Request):
    approved = request.query_params.get("approved") == "true"
    title = "Device connected." if approved else "Request denied."
    return templates.TemplateResponse(
        request,
        "message.html", ctx(request, title, body="You can close this window.")
    )


# ── Public app directory ─────────────────────────────────────────────────────


@app.get("/apps")
async def apps_page(request: Request):
    user = await current_user(request)
    _, data = await get_json(request, "/api/v1/apps/public")
    return templates.TemplateResponse(
        request,
        "apps.html", ctx(request, "Applications", user=user, apps=(data or {}).get("apps", []))
    )


# ── Password reset / generic message / sign-out ──────────────────────────────


@app.get("/forgot-password")
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        ctx(request, "Forgot Password", error=request.query_params.get("error", "")),
    )


@app.get("/reset-password")
async def reset_password_page(request: Request):
    q = request.query_params
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        ctx(request, "Reset Password", token=q.get("token", ""), error=q.get("error", "")),
    )


@app.get("/message")
async def message_page(request: Request):
    q = request.query_params
    return templates.TemplateResponse(
        request,
        "message.html", ctx(request, q.get("title", "Notice"), body=q.get("body", ""))
    )


@app.get("/logout")
async def logout_page(request: Request):
    q = request.query_params
    redirect_to = q.get("redirect_to", "")
    return templates.TemplateResponse(
        request,
        "logout.html",
        ctx(
            request, "Signing Out", uris=q.getlist("uri"), redirect_to=redirect_to,
            redirect_to_json=json.dumps(redirect_to),
        ),
    )


# ── Static assets, then the catch-all proxy (must stay last: Starlette tries
# routes in registration order, so every page route above gets first refusal
# and only unmatched paths/methods fall through to this) ────────────────────

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def backend_proxy(path: str, request: Request):
    return await proxy(request, path)
