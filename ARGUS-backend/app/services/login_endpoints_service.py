"""Dashboard-prepared login endpoints (API or page URL) for modal / manual cases."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse, urlunparse

from diagnosis.replay.normalize import collect_probe_base_urls
from app.services.zap_util import probe_url
from app.services.base_urls_service import CONFIG_PATHS

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


def _docker_host_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in {"localhost", "127.0.0.1"}:
        return url
    netloc = "host.docker.internal"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def _load_config_payload(path: Path) -> dict[str, Any]:
    import yaml

    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _write_config_payload(path: Path, payload: dict[str, Any]) -> None:
    import yaml

    path.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _resolve_for_config(raw_url: str, raw_config: dict[str, Any], *, docker: bool) -> str:
    resolved = resolve_login_endpoint_url(raw_url, raw_config)
    if not resolved:
        return ""
    return _docker_host_url(resolved) if docker else resolved


def _pick_role_login_url(login_urls: list[str]) -> str:
    return next((url for url in login_urls if "admin" in urlparse(url).path.lower()), login_urls[0])


def _patch_role_login_config(raw: dict[str, Any], login_urls: list[str]) -> None:
    diagnosis = dict(raw.get("diagnosis_1_6") or {})
    role_targets = dict(diagnosis.get("role_login_targets") or {})
    role_paths = dict(diagnosis.get("role_login_paths") or {})

    if login_urls:
        role_url = _pick_role_login_url(login_urls)
        parsed = urlparse(role_url)
        role_targets["admin"] = f"{parsed.scheme}://{parsed.netloc}"
        role_paths["admin"] = parsed.path or "/"
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
    raw["diagnosis_1_6"] = diagnosis


def sync_config_login_urls(endpoints: list[dict[str, str]]) -> None:
    raw_urls = [str(row.get("url") or "").strip() for row in endpoints if row.get("url")]

    for path in CONFIG_PATHS:
        raw = _load_config_payload(path)
        if not raw:
            continue
        docker = path.name == "config.docker.yaml"
        seen: set[str] = set()
        login_urls: list[str] = []
        for raw_url in raw_urls:
            resolved = _resolve_for_config(raw_url, raw, docker=docker)
            if resolved and resolved not in seen:
                login_urls.append(resolved)
                seen.add(resolved)
        auth = dict(raw.get("auth") or {})
        if login_urls:
            auth["login_urls"] = login_urls
        else:
            auth.pop("login_urls", None)
        raw["auth"] = auth
        _patch_role_login_config(raw, login_urls)
        _write_config_payload(path, raw)


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
    sync_config_login_urls(normalized)
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
