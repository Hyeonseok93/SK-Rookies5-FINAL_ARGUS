"""Dashboard inventory adapters for diagnosis 1-6."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def saved_base_urls(data_dir: Path) -> list[str]:
    raw = _load_json(data_dir / "base-urls.json")
    urls: list[str] = []
    for item in raw.get("urls") or []:
        if isinstance(item, dict) and item.get("url"):
            urls.append(str(item["url"]).rstrip("/"))
    return urls


def login_base_url(data_dir: Path, preferred_target: str | None = None) -> str:
    target_netloc = urlparse(preferred_target or "").netloc
    fallback = ""
    raw = _load_json(data_dir / "login-endpoints.json")
    for row in raw.get("endpoints") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("kind") or "api") != "api":
            continue
        parsed = urlparse(str(row.get("url") or "").strip())
        if not parsed.scheme or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if not fallback:
            fallback = base
        if target_netloc and parsed.netloc == target_netloc:
            return base
    return fallback


def inventory_base_urls(data_dir: Path) -> list[str]:
    raw = _load_json(data_dir / "api-tree-ready.json") or _load_json(data_dir / "api-tree.json")
    urls: list[str] = []
    for ep in raw.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        base = str(ep.get("base_url") or "").rstrip("/")
        kind = str(ep.get("kind") or "")
        if base and kind != "frontend" and base not in urls:
            urls.append(base)
    return urls


def resolve_target(data_dir: Path, raw_config: dict[str, Any], configured: str | None = None) -> str:
    if configured:
        return str(configured).rstrip("/")
    bases = saved_base_urls(data_dir) or inventory_base_urls(data_dir)
    login_base = login_base_url(data_dir)
    if login_base and login_base in bases:
        return login_base
    if login_base:
        return login_base
    api_like_bases = [u for u in bases if not urlparse(u).netloc.endswith(":5173")]
    if api_like_bases:
        return api_like_bases[0].rstrip("/")
    if bases:
        return bases[0].rstrip("/")
    for item in raw_config.get("targets") or []:
        if isinstance(item, dict) and item.get("base_url"):
            return str(item["base_url"]).rstrip("/")
    return "http://localhost:8080"


def latest_openapi_spec(data_dir: Path) -> Path | None:
    try:
        from inventory.load import find_openapi_spec

        found = find_openapi_spec(data_dir)
        if found and found.is_file():
            return found
    except Exception:
        pass

    uploads = data_dir / "uploads"
    if not uploads.is_dir():
        return None
    candidates: list[Path] = []
    for pattern in ("*/openapi.json", "*/openapi.yaml", "*/openapi.yml"):
        candidates.extend(uploads.glob(pattern))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime).resolve()


def login_override(data_dir: Path, target: str) -> dict[str, str]:
    raw = _load_json(data_dir / "login-endpoints.json")
    target_netloc = urlparse(target).netloc
    fallback: dict[str, str] = {}
    for row in raw.get("endpoints") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("kind") or "api") != "api":
            continue
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        item = {
            "login_target": f"{parsed.scheme}://{parsed.netloc}",
            "login_path": parsed.path or "/",
        }
        if not fallback:
            fallback = item
        if parsed.netloc == target_netloc:
            return item
    return fallback
