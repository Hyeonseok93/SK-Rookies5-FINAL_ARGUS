"""Retention for data/uploads batch directories."""

from __future__ import annotations

import shutil
from pathlib import Path

DEFAULT_MAX_UPLOAD_BATCHES = 5


def _batch_mtime(batch_dir: Path) -> float:
    try:
        return batch_dir.stat().st_mtime
    except OSError:
        return 0.0


def prune_upload_batches(
    uploads_dir: Path,
    *,
    keep_max: int = DEFAULT_MAX_UPLOAD_BATCHES,
) -> list[str]:
    """Drop oldest upload batch folders when more than *keep_max* exist."""
    if keep_max < 1 or not uploads_dir.is_dir():
        return []

    batches = [p for p in uploads_dir.iterdir() if p.is_dir()]
    if len(batches) <= keep_max:
        return []

    batches.sort(key=_batch_mtime, reverse=True)
    removed: list[str] = []
    for old in batches[keep_max:]:
        shutil.rmtree(old, ignore_errors=True)
        removed.append(old.name)
    return removed
