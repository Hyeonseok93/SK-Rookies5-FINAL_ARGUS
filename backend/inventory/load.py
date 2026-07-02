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


def find_openapi_specs(data_dir: Path) -> list[Path]:
    """All uploaded OpenAPI specs referenced by the current ZAP bundle."""
    from inventory.upload_batch import resolve_openapi_ref

    bundle_path = data_dir / "zap-inventory-bundle.json"
    if bundle_path.is_file():
        raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        found_specs: list[Path] = []
        for item in raw.get("openapi_imports") or []:
            found = resolve_openapi_ref(data_dir, str(item.get("file", "")))
            if found is not None:
                found_specs.append(found)
        if found_specs:
            return found_specs

    uploads = data_dir / "uploads"
    if not uploads.is_dir():
        return []

    patterns = ("*/openapi*.json", "*/openapi*.yaml", "*/openapi*.yml")
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(uploads.glob(pattern))
    if not candidates:
        return []
    newest_parent = max(candidates, key=lambda p: p.stat().st_mtime).parent
    return sorted(path.resolve() for path in candidates if path.parent == newest_parent)


def find_openapi_spec(data_dir: Path) -> Path | None:
    """Backward-compatible first-spec helper."""
    specs = find_openapi_specs(data_dir)
    return specs[0] if specs else None
