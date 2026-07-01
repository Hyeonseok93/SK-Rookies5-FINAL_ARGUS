from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
BASE_URLS_PATH = DATA_DIR / "base-urls.json"


def _normalize_entry(raw: dict[str, Any]) -> dict[str, Any] | None:
    url = str(raw.get("url", "")).strip().rstrip("/")
    entry_id = str(raw.get("id") or "").strip() or uuid.uuid4().hex
    if not url:
        return None
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}"
    return {"id": entry_id, "url": url}


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
    return load_base_urls()


def resolved_base_url_strings() -> list[str]:
    return [u["url"] for u in load_base_urls()["urls"]]
