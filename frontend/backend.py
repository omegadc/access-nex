"""Talking to the Go backend: both the transparent reverse proxy (for
everything this frontend doesn't render itself — /token, /authorize,
/api/v1/*, /api/admin/*, ...) and a small helper for page handlers that need
to fetch data server-side before rendering a template.

Same-origin from the browser's point of view either way: every request
lands on this frontend's origin first, so the Go session cookie set via a
proxied response is sent right back on the next request, no CORS needed.
"""

from __future__ import annotations

import httpx
from fastapi import Request
from starlette.responses import Response

from .config import settings

# Headers that must not be blindly forwarded in either direction: they
# describe the *transport* of one hop, not the message, and stale/incorrect
# values (a mismatched Content-Length after we've re-encoded, a
# Connection/Transfer-Encoding meant for the other hop) break the response.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
}


def _scoped_client(request: Request) -> httpx.AsyncClient:
    """A client for exactly one incoming request, sharing the app-wide
    connection pool (via a shared transport) but with its own empty cookie
    jar.

    httpx.AsyncClient tracks cookies itself: it merges its jar into every
    outgoing request and updates that same jar from every Set-Cookie it
    receives. A client shared across *all* browsers' requests (as a single
    long-lived app.state.http_client) would therefore accumulate one user's
    session cookie into its jar and start attaching it to everyone else's
    proxied requests too — a cross-user session leak. Building a
    short-lived client per request keeps the (expensive) connection pool
    shared while keeping cookie state (cheap to recreate) private to this
    one request, which is the only sane place for it to live: the browser's
    own Cookie header, forwarded explicitly below, not httpx's jar.
    """
    return httpx.AsyncClient(
        transport=request.app.state.http_transport,
        timeout=settings.backend_timeout,
        follow_redirects=False,
    )


async def api(request: Request, method: str, path: str, **kwargs) -> httpx.Response:
    """Call a Go JSON endpoint on the frontend's behalf, forwarding the
    browser's cookies (so /api/v1/* session auth works) but not following
    redirects (a 401/redirect from the backend is meaningful to the caller).
    Used by page routes to fetch the data they render — not by the raw
    passthrough proxy, which forwards the whole request verbatim instead.
    """
    headers = dict(kwargs.pop("headers", {}) or {})
    cookie = request.headers.get("cookie")
    if cookie:
        headers.setdefault("cookie", cookie)
    async with _scoped_client(request) as client:
        return await client.request(
            method, f"{settings.backend_url}{path}", headers=headers, **kwargs
        )


async def proxy(request: Request, path: str) -> Response:
    """Forward a request byte-for-byte to the Go backend and relay its
    response byte-for-byte back, including redirects (a bare Location
    header, followed by the browser as its own new request) and multiple
    Set-Cookie headers. This is the fallback for every path the frontend
    doesn't render a template for itself: the OIDC/OAuth2 endpoints,
    /api/v1/*, /api/admin/*, /metrics, form submissions the rendered pages
    post to, etc.
    """
    body = await request.body()
    headers = [
        (k, v)
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    ]
    async with _scoped_client(request) as client:
        upstream = await client.request(
            request.method,
            f"{settings.backend_url}/{path}",
            params=request.query_params,
            headers=headers,
            content=body,
        )
    response = Response(content=upstream.content, status_code=upstream.status_code)
    # Response(headers=...) only accepts a dict, which would collapse
    # multiple Set-Cookie headers into one — set raw_headers directly
    # instead so every header (Set-Cookie included) survives the hop.
    # Content-Length is excluded above and recomputed here to match
    # upstream.content exactly (it's the actual bytes on this response).
    response.raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1"))
        for k, v in upstream.headers.multi_items()
        if k.lower() not in _HOP_BY_HOP
    ]
    response.raw_headers.append((b"content-length", str(len(response.body)).encode("latin-1")))
    return response


async def get_json(request: Request, path: str, **kwargs):
    """GET path and return (status_code, json_or_None)."""
    resp = await api(request, "GET", path, **kwargs)
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, data


async def current_user(request: Request) -> dict | None:
    """The signed-in user's profile (GET /api/v1/me), or None if there
    isn't a valid session. Used by nearly every page to decide what to show.
    """
    status, data = await get_json(request, "/api/v1/me")
    return data if status == 200 else None
