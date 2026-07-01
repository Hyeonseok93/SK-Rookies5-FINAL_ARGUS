"""Persist response bodies and replay manifests on disk."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def body_fingerprint(body: bytes) -> dict[str, Any]:
    return {
        "sha256": hashlib.sha256(body).hexdigest(),
        "size": len(body),
    }


def guess_extension(content_type: str, body: bytes) -> str:
    ctype = (content_type or "").lower()
    if "pdf" in ctype or body.startswith(b"%PDF"):
        return ".pdf"
    if "json" in ctype:
        return ".json"
    if "html" in ctype:
        return ".html"
    if "xml" in ctype:
        return ".xml"
    if "text" in ctype:
        return ".txt"
    return ".bin"


def save_response_artifact(
    artifacts_dir: Path,
    step_id: str,
    body: bytes,
    *,
    content_type: str = "",
) -> str:
    """Write response bytes; return relative artifact path from artifacts_dir parent."""
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    ext = guess_extension(content_type, body)
    filename = f"{step_id}_response{ext}"
    path = artifacts_dir / filename
    path.write_bytes(body)
    return filename


def save_manifest(artifacts_dir: Path, manifest: dict[str, Any]) -> Path:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    path = artifacts_dir / "manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
