"""Helpers for data/uploads/{batch-id}/ attack-surface upload batches."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def ensure_batch_dir(uploads_dir: Path, batch_id: str) -> Path:
    batch_dir = uploads_dir / batch_id
    batch_dir.mkdir(parents=True, exist_ok=True)
    return batch_dir


def write_batch_manifest(
    batch_dir: Path,
    *,
    batch_id: str,
    url_list: str | None = None,
    api_list: str | None = None,
    openapi: str | None = None,
) -> Path:
    """Write manifest.json listing files stored in this batch (relative names)."""
    manifest: dict[str, Any] = {
        "batch_id": batch_id,
        "created_at": datetime.now(UTC).isoformat(),
        "sources": {
            "url_list": url_list,
            "api_list": api_list,
            "openapi": openapi,
        },
    }
    path = batch_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def openapi_ref_for_bundle(spec_path: Path, data_dir: Path) -> str:
    """Store upload path relative to data_dir when possible (survives path portability)."""
    resolved = spec_path.resolve()
    try:
        return resolved.relative_to(data_dir.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def resolve_openapi_ref(data_dir: Path, ref: str) -> Path | None:
    """Resolve bundle manifest or relative upload path to an on-disk spec file."""
    if not ref:
        return None
    p = Path(ref)
    if p.is_file():
        return p.resolve()
    candidate = (data_dir / ref).resolve()
    if candidate.is_file():
        return candidate
    return None
