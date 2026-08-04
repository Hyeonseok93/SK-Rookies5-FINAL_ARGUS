from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

BASE_URL_KINDS = frozenset({"api", "frontend", "api-and-frontend"})


def _normalize_entry(raw: dict[str, Any]) -> dict[str, Any] | None:
    url = str(raw.get("url", "")).strip().rstrip("/")
    entry_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}"
    kind = str(raw.get("kind") or "api").strip().lower()
    if kind not in BASE_URL_KINDS:
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


def _runtime_url(url: str) -> str:
    return _docker_host_url(url) if os.path.exists("/.dockerenv") else url


def _target_name(url: str, index: int) -> str:
    parsed = urlparse(url)
    port = parsed.port
    if port == 8081:
        return "admin-api"
    if port == 8080:
        return "api" if index == 0 else f"api-{index + 1}"
    return f"target-{index + 1}"


def apply_base_urls_to_raw_config(raw: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge dashboard base URLs into an in-memory config dict (no shared yaml write)."""
    payload = dict(raw)
    inventory = dict(payload.get("inventory") or {})
    markdown = dict(inventory.get("markdown") or {})
    openapi = dict(inventory.get("openapi") or {})

    frontend_urls = [
        str(entry["url"])
        for entry in entries
        if entry.get("kind") in {"frontend", "api-and-frontend"}
    ]
    backend_urls = [
        str(entry["url"])
        for entry in entries
        if entry.get("kind") in {"api", "api-and-frontend"}
    ]
    docker = os.path.exists("/.dockerenv")
    target_urls = [_docker_host_url(url) if docker else url for url in backend_urls]
    frontend_url = frontend_urls[0] if frontend_urls else ""

    payload["targets"] = [
        {"name": _target_name(url, index), "base_url": url}
        for index, url in enumerate(target_urls)
    ]

    if frontend_url:
        markdown["frontend_base_url"] = frontend_url
        markdown["include_frontend_routes"] = True
    else:
        markdown["frontend_base_url"] = ""
        markdown["include_frontend_routes"] = False

    if target_urls:
        openapi["base_url"] = target_urls[0]
    else:
        openapi["base_url"] = ""

    inventory["markdown"] = markdown
    inventory["openapi"] = openapi
    inventory["base_urls"] = list(dict.fromkeys(target_urls + frontend_urls))
    payload["inventory"] = inventory
    return payload


def load_base_urls(data_dir: Path) -> dict[str, Any]:
    urls: list[dict[str, Any]] = []
    path = data_dir / "base-urls.json"
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw.get("urls", []):
            normalized = _normalize_entry(entry)
            if normalized:
                urls.append(normalized)
    return {"urls": urls}


def save_base_urls(data_dir: Path, urls: list[dict[str, Any]]) -> dict[str, Any]:
    data_dir.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, Any]] = []
    for entry in urls:
        item = _normalize_entry(entry)
        if item:
            normalized.append(item)
    payload = {"urls": normalized}
    (data_dir / "base-urls.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return load_base_urls(data_dir)


def resolved_base_url_strings(data_dir: Path) -> list[str]:
    return [u["url"] for u in load_base_urls(data_dir)["urls"]]


def resolved_base_urls_by_kind(data_dir: Path) -> tuple[list[str], list[str]]:
    """Return (api bases, frontend bases) without guessing from ports or names."""
    api: list[str] = []
    frontend: list[str] = []
    for entry in load_base_urls(data_dir)["urls"]:
        url = _runtime_url(str(entry["url"]))
        kind = entry.get("kind") or "api"
        if kind in {"api", "api-and-frontend"} and url not in api:
            api.append(url)
        if kind in {"frontend", "api-and-frontend"} and url not in frontend:
            frontend.append(url)
    return api, frontend
