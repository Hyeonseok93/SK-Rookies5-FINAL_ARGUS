"""Probe URL rewriting for Docker/local runs."""

from __future__ import annotations

import os
from urllib.parse import urlparse


def _probe_host() -> str:
    return os.environ.get("ARGUS_PROBE_HOST", "").strip()


def probe_url(url: str) -> str:
    """Rewrite localhost only when ARGUS_PROBE_HOST is set (Docker)."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host not in ("localhost", "127.0.0.1"):
        return url
    probe_host = _probe_host()
    if not probe_host:
        return url
    port = f":{parsed.port}" if parsed.port else ""
    scheme = parsed.scheme or "http"
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{probe_host}{port}{path}{query}"


def probe_base_url(base_url: str) -> str:
    """Map localhost base URL to probe host when ARGUS_PROBE_HOST is set."""
    parsed = urlparse(base_url.rstrip("/"))
    host = (parsed.hostname or "").lower()
    if host not in ("localhost", "127.0.0.1"):
        return base_url.rstrip("/")
    probe_host = _probe_host()
    if not probe_host:
        return base_url.rstrip("/")
    port = f":{parsed.port}" if parsed.port else ""
    scheme = parsed.scheme or "http"
    return f"{scheme}://{probe_host}{port}"
