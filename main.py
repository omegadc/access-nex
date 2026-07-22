"""Entry point for the Python/FastAPI frontend.

Run with: uvicorn main:app --host 0.0.0.0 --port 8000

This process renders every browser-facing page and proxies everything else
to the Go backend (internal/server) — see docs/FRONTEND.md. Point a browser
at this service, not directly at the Go backend's port, in normal use;
ACCESS_NEX_BACKEND_URL (default http://localhost:8080) tells it where that
backend is.
"""

from frontend.app import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
