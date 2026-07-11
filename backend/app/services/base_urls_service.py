from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import yaml

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
BACKEND_ROOT = DATA_DIR.parent
BASE_URLS_PATH = DATA_DIR / "base-urls.json"
CONFIG_PATHS = (BACKEND_ROOT / "config.yaml", BACKEND_ROOT / "config.docker.yaml")
FRONTEND_PORTS = frozenset({3000, 4173, 5173, 5174})


def _normalize_entry(raw: dict[str, Any]) -> dict[str, Any] | None:
    url = str(raw.get("url", "")).strip().rstrip("/")
    entry_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}"
    return {"id": entry_id, "url": url}


def _is_frontend_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.port in FRONTEND_PORTS:
        return True
    return "frontend" in (parsed.hostname or "").lower()


def _docker_host_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in {"localhost", "127.0.0.1"}:
        return url
    netloc = "host.docker.internal"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def _target_name(url: str, index: int) -> str:
    parsed = urlparse(url)
    port = parsed.port
    if port == 8081:
        return "admin-api"
    if port == 8080:
        return "api" if index == 0 else f"api-{index + 1}"
    return f"target-{index + 1}"


def _patch_config_payload(raw: dict[str, Any], urls: list[str], *, docker: bool) -> dict[str, Any]:
    payload = dict(raw)
    inventory = dict(payload.get("inventory") or {})
    markdown = dict(inventory.get("markdown") or {})
    openapi = dict(inventory.get("openapi") or {})

    frontend_url = next((url for url in urls if _is_frontend_url(url)), "")
    backend_urls = [url for url in urls if url != frontend_url]
    if not backend_urls and urls:
        backend_urls = [urls[0]]

    target_urls = [_docker_host_url(url) if docker else url for url in backend_urls]
    payload["targets"] = [
        {"name": _target_name(url, index), "base_url": url}
        for index, url in enumerate(target_urls)
    ]

    if frontend_url:
        markdown["frontend_base_url"] = frontend_url
        markdown["include_frontend_routes"] = True

    if target_urls:
        openapi["base_url"] = target_urls[0]

    inventory["markdown"] = markdown
    inventory["openapi"] = openapi
    inventory["base_urls"] = target_urls + ([frontend_url] if frontend_url else [])
    payload["inventory"] = inventory
    return payload


def sync_config_files(urls: list[dict[str, Any]]) -> None:
    strings = [str(item["url"]).rstrip("/") for item in urls if item.get("url")]
    if not strings:
        return

    for path in CONFIG_PATHS:
        if not path.is_file():
            continue
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        patched = _patch_config_payload(raw, strings, docker=path.name == "config.docker.yaml")
        path.write_text(
            yaml.safe_dump(patched, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )


def load_base_urls() -> dict[str, Any]:
    urls: list[dict[str, Any]] = []
    if BASE_URLS_PATH.is_file():
        raw = json.loads(BASE_URLS_PATH.read_text(encoding="utf-8"))
        for entry in raw.get("urls", []):
            normalized = _normalize_entry(entry)
            if normalized:
                urls.append(normalized)
    return {"urls": urls}


def save_base_urls(urls: list[dict[str, Any]]) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    normalized: list[dict[str, Any]] = []
    for entry in urls:
        item = _normalize_entry(entry)
        if item:
            normalized.append(item)
    payload = {"urls": normalized}
    BASE_URLS_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    sync_config_files(normalized)
    return load_base_urls()


def resolved_base_url_strings() -> list[str]:
    return [u["url"] for u in load_base_urls()["urls"]]
