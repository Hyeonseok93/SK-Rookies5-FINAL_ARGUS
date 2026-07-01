"""Load persisted inventory artifacts from the data directory."""

from __future__ import annotations

import json
from pathlib import Path

from inventory.schema import ApiTree

BEST_TREE_FILES = ("api-tree-verified.json", "api-tree-ready.json", "api-tree.json")


def load_best_api_tree(data_dir: Path | None) -> ApiTree | None:
    """Prefer verified tree, then ready, then legacy api-tree.json."""
    if data_dir is None:
        return None
    for name in BEST_TREE_FILES:
        path = data_dir / name
        if path.is_file():
            return ApiTree.load(path)
    return None


# Alias used across diagnosis modules
load_api_tree = load_best_api_tree


def load_cached_tree(data_dir: Path, *, inventory: str = "ready") -> ApiTree | None:
    """Router-facing loader: verified-only vs ready/legacy fallback."""
    if inventory == "verified":
        path = data_dir / "api-tree-verified.json"
        return ApiTree.load(path) if path.is_file() else None
    for name in ("api-tree-ready.json", "api-tree.json"):
        path = data_dir / name
        if path.is_file():
            return ApiTree.load(path)
    return None


def find_openapi_spec(data_dir: Path) -> Path | None:
    """Latest uploaded OpenAPI spec from bundle metadata or uploads batch."""
    bundle_path = data_dir / "zap-inventory-bundle.json"
    if bundle_path.is_file():
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        for item in raw.get("openapi_imports") or []:
            p = Path(str(item.get("file", "")))
            if p.is_file():
                return p
    uploads = data_dir / "uploads"
    if uploads.is_dir():
        patterns = ("*/openapi.json", "*/openapi.yaml", "*/openapi.yml")
        candidates: list[Path] = []
        for pattern in patterns:
            candidates.extend(uploads.glob(pattern))
        if candidates:
            return max(candidates, key=lambda p: p.stat().st_mtime)
    return None
