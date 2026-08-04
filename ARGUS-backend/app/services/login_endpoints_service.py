"""Dashboard-prepared login endpoints (API or page URL) for modal / manual cases."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from diagnosis.replay.normalize import collect_probe_base_urls
from app.services.zap_util import probe_url
from app.workspace import current_data_dir, require_data_dir

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


def apply_login_urls_to_raw_config(
    raw: dict[str, Any],
    endpoints: list[dict[str, str]],
) -> dict[str, Any]:
    """Merge dashboard login endpoints into in-memory config (no shared yaml write)."""
    payload = dict(raw)
    raw_urls = [str(row.get("url") or "").strip() for row in endpoints if row.get("url")]
    seen: set[str] = set()
    login_urls: list[str] = []
    for raw_url in raw_urls:
        resolved = resolve_login_endpoint_url(raw_url, payload)
        if resolved and resolved not in seen:
            login_urls.append(resolved)
            seen.add(resolved)

    auth = dict(payload.get("auth") or {})
    if login_urls:
        auth["login_urls"] = login_urls
    else:
        auth.pop("login_urls", None)
    payload["auth"] = auth

    diagnosis = dict(payload.get("diagnosis_1_6") or {})
    role_targets = dict(diagnosis.get("role_login_targets") or {})
    role_paths = dict(diagnosis.get("role_login_paths") or {})
    if login_urls:
        role_url = next(
            (url for url in login_urls if "admin" in urlparse(url).path.lower()),
            login_urls[0],
        )
        parsed = urlparse(role_url)
        role_targets["admin"] = f"{parsed.scheme}://{parsed.netloc}"
        role_paths["admin"] = parsed.path or "/"
        diagnosis["role_login_targets"] = role_targets
        diagnosis["role_login_paths"] = role_paths
    else:
        role_targets.pop("admin", None)
        role_paths.pop("admin", None)
        if role_targets:
            diagnosis["role_login_targets"] = role_targets
        else:
            diagnosis.pop("role_login_targets", None)
        if role_paths:
            diagnosis["role_login_paths"] = role_paths
        else:
            diagnosis.pop("role_login_paths", None)
    payload["diagnosis_1_6"] = diagnosis
    return payload


def load_login_endpoints(data_dir: Path | None = None) -> dict[str, Any]:
    data_dir = require_data_dir(data_dir)
    endpoints: list[dict[str, str]] = []
    path = data_dir / "login-endpoints.json"
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw.get("endpoints", []):
            normalized = _normalize_entry(entry)
            if normalized:
                endpoints.append(normalized)
    return {"endpoints": endpoints}


def save_login_endpoints(data_dir: Path | None, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    data_dir = require_data_dir(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, str]] = []
    for entry in endpoints:
        item = _normalize_entry(entry)
        if item:
            normalized.append(item)
    payload = {"endpoints": normalized}
    (data_dir / "login-endpoints.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return load_login_endpoints(data_dir)


def dashboard_login_entries(
    raw_config: dict[str, Any] | None = None,
    data_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Resolved manual login endpoints from dashboard JSON."""
    resolved = data_dir if data_dir is not None else current_data_dir()
    if resolved is None:
        return []
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in load_login_endpoints(resolved).get("endpoints", []):
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
