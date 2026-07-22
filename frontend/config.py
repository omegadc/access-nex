"""Environment-driven configuration for the frontend service."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Base URL of the Go backend this frontend renders pages for and
    # proxies everything else to. In Docker Compose this is the other
    # service's name (e.g. http://access-nex:8080); locally it's whatever
    # `access-nex server --addr` is bound to.
    backend_url: str = os.getenv("ACCESS_NEX_BACKEND_URL", "http://localhost:8080")

    # Seconds to wait on a single backend request before giving up. /authorize
    # and friends are all fast, in-process calls on the Go side, so this is
    # generous headroom rather than an expected normal wait.
    backend_timeout: float = float(os.getenv("ACCESS_NEX_BACKEND_TIMEOUT", "15"))

    # Product name shown in page titles/headers — kept out of templates so
    # a fork/rebrand doesn't need to touch every .html file.
    brand: str = os.getenv("ACCESS_NEX_BRAND", "Access-Nex")


settings = Settings()
