"""Dashboard-prepared login endpoints (API or page URL) for modal / manual cases."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls
from app.services.zap_util import probe_url

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
LOGIN_ENDPOINTS_PATH = DATA_DIR / "login-endpoints.json"

LoginKind = Literal["api", "page"]


def _default_bases(raw_config: dict[str, Any] | None) -> list[str]:
    return collect_probe_base_urls(raw_config)


def resolve_login_endpoint_url(raw: str, raw_config: dict[str, Any] | None = None) -> str:
    """Turn absolute URL or path into a probe-ready login URL."""
    s = str(raw).strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        return probe_url(s.rstrip("/"))
    bases = _default_bases(raw_config)
    if not bases:
        return ""
    base = bases[0].rstrip("/")
    if s.startswith("/"):
        return probe_url(f"{base}{s}")
    return probe_url(f"{base}/{s.lstrip('/')}")


def _normalize_entry(raw: dict[str, Any]) -> dict[str, str] | None:
    url = str(raw.get("url") or "").strip()
    entry_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex
    if not url:
        return None
    kind = str(raw.get("kind") or "api").strip().lower()
    if kind not in ("api", "page"):
        kind = "api"
    return {"id": entry_id, "url": url, "kind": kind}


def load_login_endpoints() -> dict[str, Any]:
    endpoints: list[dict[str, str]] = []
    if LOGIN_ENDPOINTS_PATH.is_file():
        raw = json.loads(LOGIN_ENDPOINTS_PATH.read_text(encoding="utf-8"))
        for entry in raw.get("endpoints", []):
            normalized = _normalize_entry(entry)
            if normalized:
                endpoints.append(normalized)
    return {"endpoints": endpoints}


def save_login_endpoints(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, str]] = []
    for entry in endpoints:
        item = _normalize_entry(entry)
        if item:
            normalized.append(item)
    payload = {"endpoints": normalized}
    LOGIN_ENDPOINTS_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return load_login_endpoints()


def dashboard_login_entries(raw_config: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """Resolved manual login endpoints from dashboard JSON."""
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in load_login_endpoints().get("endpoints", []):
        raw_url = str(row.get("url") or "").strip()
        if not raw_url:
            continue
        if raw_url.startswith("http://") or raw_url.startswith("https://"):
            logical_base = f"{urlparse(raw_url).scheme}://{urlparse(raw_url).netloc}".rstrip("/")
        else:
            bases = collect_probe_base_urls(raw_config)
            logical_base = bases[0].rstrip("/") if bases else ""
        resolved = resolve_login_endpoint_url(raw_url, raw_config)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        path = urlparse(resolved).path.rstrip("/") or "/"
        label = path.split("/")[-1] or "login"
        entries.append(
            {
                "url": resolved,
                "label": label,
                "base_url": logical_base or f"{urlparse(resolved).scheme}://{urlparse(resolved).netloc}",
                "source": "dashboard",
                "kind": str(row.get("kind") or "api"),
            }
        )
    return entries
